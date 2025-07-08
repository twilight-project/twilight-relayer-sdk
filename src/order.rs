//! Create and Broadcast a Trader Order and Settlement Transaction
//! Creates a ScriptTransaction
use address::Network;
use curve25519_dalek::scalar::Scalar;
use quisquislib::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use transaction::{ScriptTransaction, Transaction};
use twilight_client_sdk::programcontroller::ContractManager;
use twilight_client_sdk::relayer_types::ClientMemoTx;
use zkschnorr::Signature;
//use merlin::Transcript;
use quisquislib::accounts::prover::SigmaProof;
lazy_static! {
    pub static ref ZKOS_SERVER_URL: String =
        std::env::var("ZKOS_SERVER_URL").expect("missing environment variable ZKOS_SERVER_URL");
}

use transactionapi::rpcclient::{
    method,
    method::Method,
    txrequest::{RpcBody, RpcRequest},
};
use zkvm::{
    merkle::CallProof,
    zkos_types::{Input, Output, StateWitness, ValueWitness},
    Witness,
};

// Prepare data for trader order creation
// creates the Input Coin and Output for the trader order
// pub fn prepare_trader_settle_order_data(
//     pk: RistrettoPublicKey,
//     encryption: CompressedRistretto,
//     order_id: String,
//     leverage: u64,
//     entry_price: u64,
//     position_size: u64,
//     order_side: u64,
//     script_address: String,
//     timebounds: u64,
// ) -> Result<(Input, Output), &'static str> {
//     //create the Verifier View of the Coin and set the Witness to 0
//     let input_sign = Input::coin(Input::set_input_for_signing(pk, encryption));

//     //create the Output Memo
//     let memo_out = Output::memo(Output::set_output_memo(
//         order_id,
//         leverage,
//         entry_price,
//         position_size,
//         order_side,
//         script_address,
//         timebounds,
//     ));

//     Ok((input_sign, memo_out))
// }

///Updates the Trader OutputMemo to reflect the latest open order price/ actual position size for client
/// This function is called by the relayer
/// @param memo : Input Memo received from the client
/// @param open_price : Open price of the order
/// @return output_memo : Output Memo created by the relayer
pub fn update_trader_output_memo(
    memo: Output,
    entry_price: u64,
    position_size: u64,
) -> Result<Output, &'static str> {
    // get the OutputMemo from Output
    let mut output_memo = match memo.as_output_data().get_output_memo() {
        Some(memo) => memo.clone(),
        None => return Err("Error in getting the output memo from the output")?,
    };
    // get the data from the memo
    let mut data = match output_memo.get_data() {
        Some(data) => data.clone(),
        None => return Err("Error in getting the data from the output memo")?,
    };
    //update position size
    data[0] = zkvm::String::from(Scalar::from(position_size));
    // update the entry price
    data[2] = zkvm::String::from(Scalar::from(entry_price));
    // update the output memo
    output_memo.set_data(data.clone());
    Ok(output_memo.to_output())
}
/// Updates the tx to reflect the latest open order price for the client
pub fn update_memo_tx_client_order(
    order_tx: &Transaction,
    entry_price: u64,
    position_size: u64,
    fee: u64,
) -> Result<ClientMemoTx, &'static str> {
    // get existing output memo
    let output_memo = order_tx.get_tx_outputs();
    // update the memo with the entry price and position size
    let updated_memo =
        update_trader_output_memo(output_memo[0].clone(), entry_price, position_size)?;
    //get input coin
    let input_coin = order_tx.get_tx_inputs();
    // get tx_data
    let mut script_tx = order_tx.to_owned().tx.to_script()?;
    let script_data = script_tx.get_tx_data();

    // create verifier view for the txn
    let (inputs, outputs, tx_data) =
        ScriptTransaction::create_verifier_view(&input_coin, &[updated_memo.clone()], script_data);
    // update the script transaction with the new verifier view
    script_tx.set_data(tx_data);
    script_tx.set_inputs(inputs);
    script_tx.set_outputs(outputs);
    script_tx.set_fee(fee);
    // create tx from script tx
    let tx = Transaction::from(script_tx);
    Ok(ClientMemoTx {
        tx,
        output: updated_memo,
    })
}

/// Creates the Script based Transaction for creating the trade order on relayer for chain
///
///@param input_coin :  Input received from the trader
///@param output_memo : Output Memo created by the trader
///@param signature : Signature over the input_coin as Verifier view sent by trader
///@param proof : Sigma proof of same value committed in Coin and Memo sent by the trader
///@param order_msg: order message serialized. CreateTraderOrder struct should be passed here. Ideally this information should be Encrypted
///@param program : Program to be run on the chain
/// @return : Transaction
///
pub fn create_trade_order(
    input_coin: Input,    // Input received from the trader
    output_memo: Output, // Output Memo created by the trader (C(Initial Margin), PositionSize, C(Leverage), EntryPrice, OrderSide
    signature: Signature, // Signature over the input_coin as Verifier view sent by trader
    proof: SigmaProof,   // Sigma proof of same value committed in Coin and Memo sent by the trader
    contract_manager: &ContractManager,
    chain_network: Network,
    fee: u64, // in satoshis
) -> Result<Transaction, &'static str> {
    //create Value witness as the witness for coin input
    let witness = Witness::ValueWitness(ValueWitness::set_value_witness(signature, proof.clone()));

    let witness_vec = [witness];

    //create input vector
    let inputs = vec![input_coin];

    //create output vector
    let outputs = vec![output_memo];

    // get the program from the contract manager
    let order_tag = "CreateTraderOrder";
    let single_program = contract_manager.get_program_by_tag(order_tag);

    // execute the program and create a proof for computations
    let program_proof = transaction::vm_run::Prover::build_proof(
        single_program.unwrap(),
        &inputs,
        &outputs,
        false,
        None,
    );

    let (program, proof) = match program_proof {
        Ok((program, proof)) => (program, proof),
        Err(_) => return Err("Error in creating program proof"),
    };

    // converts inputs and outputs to hide the encrypted data using verifier view and update witness index
    let (inputs, outputs, _) = ScriptTransaction::create_verifier_view(&inputs, &outputs, None);

    // create callproof for the program
    let call_proof = contract_manager.create_call_proof(chain_network, order_tag)?;

    let script_tx = ScriptTransaction::set_script_transaction(
        0u64,
        fee,
        0u64,
        inputs.len() as u8,
        outputs.len() as u8,
        witness_vec.len() as u8,
        inputs.to_vec(),
        outputs.to_vec(),
        program,
        call_proof,
        proof,
        witness_vec.to_vec(),
        None,
    );
    Ok(Transaction::from(script_tx))
}

/// broadcasts trader order transaction to the ZKOS Server on chain
///
pub fn broadcast_trade_order(tx: Transaction) -> Result<String, String> {
    let tx_send: RpcBody<Transaction> = RpcRequest::new(tx, Method::txCommit);
    let res = tx_send.send(ZKOS_SERVER_URL.clone());
    match res {
        Ok(rpc_response) => match method::GetTxCommit::get_txhash(rpc_response) {
            Ok(tx_hash) => Ok(tx_hash),
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg)),
        },
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg)),
    }
}

/// creates the Trade order settlement transaction
/// Client send a Memo Output with the settlement request
/// relayer creats the Input Memo and Output Coin
/// relayer creates the Input State and Output State
///
/*******  Inputs *******/
// @input client_output_memo : Output Memo(Prover View) use to create the Order tx sent by the trader
// @input payment : coin value to be created as the payment for Trader
// @input contract_manager: Program manager to get the program/call proof for the transaction
// @input chain_network: Network to be used for the transaction
// @input fee: fee to be paid for the transaction
// @input contract_owner_address: Address of the CONTRACT State Owner
// @input input_state_output: Previous Output State Prover View to be used as Input State for this tx
// @input output_state: Output State for this tx
// @input error: Error used for proof program execution
// @input sk: Secret key of the CONTRACT State Owner
// @input pk: Public key of the CONTRACT State Owner
/*******  Ouputs *******/
// @Output Transaction: Complete chain transaction with the program and proof to be relayed to the Chain
#[allow(clippy::too_many_arguments)]
pub fn settle_trader_order(
    client_output_memo: Output, //(C(Initial Margin), PositionSize, C(Leverage), EntryPrice, OrderSide)
    payment: u64,               // Available margin to be sent to the trader
    contract_manager: &ContractManager,
    chain_network: Network,
    fee: u64,                              // in satoshis
    contract_owner_address: String,        // Address of the Contract State Owner
    input_state_output: Output, // Previous Output State Prover View to be used as Input State for this tx
    output_state: Output,       // Output State for this tx
    error: i128,                // Error used for proof program execution
    margin_difference: u64,     // Margin difference on the exchange
    settle_price: u64,          // Settle price of the order
    contract_owner_sk: RistrettoSecretKey, // Secret key of the Contract State Owner
    contract_owner_pk: RistrettoPublicKey, // Public key of the Contract State Owner
    program_tag: String,
) -> Result<Transaction, String> {
    // create the input_memo for the settlement using client_output_memo
    // get hex address from the output memo
    let client_address = match client_output_memo.as_output_data().get_owner_address() {
        Some(address) => address,
        None => return Err("Error in getting the client address from the output memo")?,
    };
    // create the input memo
    let (input_memo, coin_memo_scalar) =
        twilight_client_sdk::chain::get_transaction_memo_input_from_address(
            client_address.clone(),
            client_output_memo.clone(),
            payment,
        )?;
    // create the outputcoin for the client payment
    let output_coin = match twilight_client_sdk::util::create_output_coin_for_trader(
        client_address.clone(),
        payment,
        coin_memo_scalar,
    ) {
        Some(output_coin) => output_coin,
        None => return Err("Error in creating the output coin for the client payment")?,
    };

    //create witness as the same value sigma proof for memo input / Coin output
    let memo_witness =
        Witness::create_witness_for_memo_input(output_coin.clone(), input_memo.clone())?;

    // create the input state based on the previous Output State and additional script data
    let input_state = create_input_state_for_trader_settlement_order(
        contract_owner_address.clone(),
        input_state_output.clone(),
        error,
        margin_difference,
    )?;

    // create witness for the State input and output
    let state_witness = Witness::State(StateWitness::create_state_witness(
        &input_state,
        &output_state,
        contract_owner_sk,
        contract_owner_pk,
        false,
    ));

    // create witness vector
    let witness_vec = vec![memo_witness, state_witness];

    // get the program from the contract manager
    //let program_tag = "SettleTraderOrder";
    let settle_program = match contract_manager.get_program_by_tag(&program_tag) {
        Ok(program) => program,
        Err(_) => return Err("Error in getting the program from the contract manager")?,
    };
    // create callproof for the program
    let call_proof: CallProof = contract_manager.create_call_proof(chain_network, &program_tag)?;

    let inputs = vec![input_memo.clone(), input_state.clone()];
    let outputs = vec![output_coin.clone(), output_state.clone()];

    // tx_date i.e., settle price
    let tx_data: zkvm::String = zkvm::String::from(Scalar::from(settle_price));
    // execute the program and create a proof for computations
    let program_proof = transaction::vm_run::Prover::build_proof(
        settle_program.clone(),
        &inputs,
        &outputs,
        false,
        Some(tx_data.clone()),
    );

    let (program, proof) = match program_proof {
        Ok((program, proof)) => (program, proof),
        Err(_) => return Err("Error in creating program proof")?,
    };
    // converts inputs and outputs to hide the encrypted data using verifier view and update witness index
    let (inputs, outputs, _) =
        ScriptTransaction::create_verifier_view(&inputs, &outputs, Some(tx_data.clone()));

    let script_tx = ScriptTransaction::set_script_transaction(
        0u64,
        fee,
        0u64,
        inputs.len() as u8,
        outputs.len() as u8,
        witness_vec.len() as u8,
        inputs.to_vec(),
        outputs.to_vec(),
        program,
        call_proof,
        proof,
        witness_vec.to_vec(),
        Some(tx_data),
    );
    Ok(Transaction::from(script_tx))
}

/// create input state for the Trade settlement Order
/// Utxo Id is fetched from the chain using the contract owner address
///
pub fn create_input_state_for_trader_settlement_order(
    contract_owner_addresss: String,
    out_state: Output,
    error: i128,
    margin_difference: u64,
) -> Result<Input, String> {
    // create SignedInteger
    let signed_integer = crate::SignedInteger::from(error);
    // convert the error to ZKVM String
    let error_scalar = signed_integer.to_scalar();

    let md = zkvm::Commitment::blinded(margin_difference);
    let settle_script_data: Vec<zkvm::String> =
        vec![zkvm::String::from(md), zkvm::String::from(error_scalar)];
    // call the client wallet function to create input state
    twilight_client_sdk::chain::get_transaction_state_input_from_address(
        contract_owner_addresss,
        out_state,
        Some(settle_script_data),
    )
}
#[cfg(test)]
mod tests {
    mod test {
        use address::{Address, Network};
        use curve25519_dalek::scalar::{self, Scalar};
        use quisquislib::{
            accounts::Account,
            elgamal::ElGamalCommitment,
            keys::{PublicKey, SecretKey},
            ristretto::{RistrettoPublicKey, RistrettoSecretKey},
        };
        use zkvm::{
            bulletproofs::ProofError,
            zkos_types::{Input, Output, OutputCoin, OutputMemo, OutputState, ValueWitness},
            Commitment, InputData, OutputData, String as ZString, Utxo, Witness,
        };

        use super::*;
        use crate::order;
        use log::{debug, error};
        #[test]
        fn test_create_trade_order_tx() {
            //create InputCoin and OutputMemo
            dotenvy::dotenv().expect("Failed loading dotenv");
            let seed = std::env::var("TEST_SEED")
                .unwrap_or_else(|_| "generate_random_test_seed()".to_string());

            //derive private key;
            let sk = SecretKey::from_bytes(seed.as_bytes());
            let mut rng = rand::thread_rng();
            let sk_in: quisquislib::ristretto::RistrettoSecretKey = SecretKey::random(&mut rng);
            let pk_in = RistrettoPublicKey::from_secret_key(&sk_in, &mut rng);
            let rscalar = Scalar::random(&mut rng);
            let commit_in = ElGamalCommitment::generate_commitment(
                &pk_in,
                rscalar.clone(),
                Scalar::from(100000u64),
            );
            let coin_acc = Account::set_account(pk_in.clone(), commit_in.clone());
            let add: Address = Address::standard_address(Network::default(), pk_in.clone());
            let out_coin = OutputCoin {
                encrypt: commit_in.clone(),
                owner: add.as_hex(),
            };
            let in_data: InputData = InputData::coin(Utxo::default(), out_coin, 0);
            let coin_in: Input = Input::coin(in_data);

            //*****  OutputMemo  *********/
            //****************************/
            let script_address =
                Address::script_address(Network::Mainnet, *Scalar::random(&mut rng).as_bytes());
            //IM
            let commit_memo = Commitment::blinded_with_factor(100000u64, rscalar.clone());
            //Leverage committed
            let leverage = Commitment::blinded(20u64);
            // entryprice in cents
            let entry_price = 43517u64;
            // PositionSize
            let position_size = 87034000000u64;
            let order_side: u64 = 1u64;
            let data: Vec<ZString> = vec![
                ZString::from(Scalar::from(position_size)),
                ZString::from(leverage),
                ZString::from(Scalar::from(entry_price)),
                ZString::from(Scalar::from(order_side)),
            ];
            let memo_out = OutputMemo {
                script_address: script_address.as_hex(),
                owner: add.as_hex(),
                commitment: commit_memo.clone(),
                data: Some(data),
                timebounds: 0,
            };
            let out_data = OutputData::Memo(memo_out);
            let memo = Output::memo(out_data);

            // create value witness
            // create InputCoin Witness
            let commit_memo_point = commit_memo.to_point();
            let witness = Witness::ValueWitness(ValueWitness::create_value_witness(
                coin_in.clone(),
                sk,
                //   memo.clone(),
                coin_acc.clone(),
                pk_in.clone(),
                commit_memo_point.clone(),
                100000u64,
                rscalar,
            ));
            let path = "../zkos-client-wallet/relayerprogram.json";
            let programs =
                twilight_client_sdk::programcontroller::ContractManager::import_program(path);
            let value_witness = witness.to_value_witness().unwrap();
            let sign = value_witness.get_signature();
            let proof = value_witness.get_value_proof();
            let tx = crate::order::create_trade_order(
                coin_in.clone(),
                memo.clone(),
                sign.clone(),
                proof.clone(),
                &programs,
                Network::Mainnet,
                1000u64,
            );
        }
        #[test]
        fn test_update_memo() {
            use zkvm::String;
            // creat a  output memo
            let mut rng = rand::thread_rng();
            let script_address =
                Address::script_address(Network::Mainnet, *Scalar::random(&mut rng).as_bytes());
            //IM
            let im = Commitment::blinded(100u64);
            let leverage = Commitment::blinded(5u64);
            // entryprice in cents
            let entry_price = 50u64;
            // PositionSize
            let position_size = 25000u64;
            let order_side: u64 = 1u64;
            let data: Vec<ZString> = vec![
                String::from(Scalar::from(position_size)),
                String::from(leverage),
                String::from(Scalar::from(entry_price)),
                String::from(Scalar::from(order_side)),
            ];
            let memo_out = OutputMemo {
                script_address: script_address.as_hex(),
                owner: "owner".to_string(),
                commitment: im.clone(),
                data: Some(data),
                timebounds: 0,
            };
            let memo = Output::memo(OutputData::Memo(memo_out));
            let entry_price = 100u64;
            let updated_memo =
                crate::order::update_trader_output_memo(memo.clone(), entry_price, 100000u64);
            log::debug!("{:?}", updated_memo);
        }
        #[test]
        fn test_trade_settle_order_stack_new() {
            let seed_client = std::env::var("TEST_SEED")
                .unwrap_or_else(|_| "generate_random_test_seed".to_string());
            //create InputMemo and OutputCoin
            //     let mut rng = rand::thread_rng();
            //     let sk: quisquislib::ristretto::RistrettoSecretKey = SecretKey::random(&mut rng);
            //     let pk = RistrettoPublicKey::from_secret_key(&sk, &mut rng);
            //     let commitment_scalar = Scalar::random(&mut rng);
            //     let commit = ElGamalCommitment::generate_commitment(
            //         &pk,
            //         commitment_scalar,
            //         Scalar::from(0u64),
            //     );
            //     let add: Address = Address::standard_address(Network::default(), pk.clone());
            //     let out_coin = OutputCoin {
            //         encrypt: commit,
            //         owner: add.as_hex(),
            //     };
            //     let coin_out: Output = Output::coin(OutputData::coin(out_coin));

            //    // *****  InputMemo  *********/
            //    // ****************************/
            //     let script_address =
            //         Address::script_address(Network::Mainnet, *Scalar::random(&mut rng).as_bytes());
            //     //IM
            //     let commit_memo = Commitment::blinded_with_factor(500u64, commitment_scalar.clone());
            //     //Leverage committed
            //     let leverage = Commitment::blinded(5u64);
            //     // entryprice in cents
            //     let entry_price = 43000u64;
            //     // PositionSize
            //     let position_size = 125000u64;
            //     let order_side: u64 = 1u64;
            //     let data: Vec<ZString> = vec![
            //         ZString::from(Scalar::from(position_size)),
            //         ZString::from(leverage),
            //         ZString::from(Scalar::from(entry_price)),
            //         ZString::from(Scalar::from(order_side)),
            //     ];
            //     let memo_out = OutputMemo {
            //         script_address: script_address.as_hex(),
            //         owner: add.as_hex(),
            //         commitment: commit_memo,
            //         data: Some(data),
            //         timebounds: 0,
            //     };
            //derive private key;
            // let sk_client = SecretKey::from_bytes(seed_client.as_bytes());
            //creating input memo from trader provided hex
            let memo_hex = "01000000010000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a00000000000000306337383939643336393733336138383662663235653036363435636161623334363638643136356462666533663062366433653230623336356332613835633739323432336263623133326233316238613666333664643633623937626635323963383035613332376162643039386530633963616566316435316661623737613062636161353032010000000000000080d1f008000000000000000000000000ce26597c700a45962191f342f4782cc557b2738a332a41ba8f66d8f20f42a60e010400000000000000030000000100000000fcab7ec28e000000000000000000000000000000000000000000000000000002000000010000000000000014000000000000000000000000000000ce26597c700a45962191f342f4782cc557b2738a332a41ba8f66d8f20f42a60e030000000100000062cc0000000000000000000000000000000000000000000000000000000000000300000001000000010000000000000000000000000000000000000000000000000000000000000000000000";
            let memo_bin = hex::decode(memo_hex).unwrap();
            let memo_out: Output = bincode::deserialize(&memo_bin).unwrap();

            // extract coin address from the memo
            let coin_address = memo_out
                .as_output_data()
                .get_owner_address()
                .unwrap()
                .clone();
            // extract outputMemo from memo
            let memo_output = memo_out.as_output_data().get_output_memo().unwrap().clone();
            log::debug!("{:?}", memo_output);
            let entry_price_scalar = Scalar::from(52322u64);
            log::debug!("Entry Price {:?}", entry_price_scalar);
            let coin_value: Commitment = Commitment::blinded(161341791u64); //(82u64); // AM to be pushed back to the user
            let memo_in = Input::memo(InputData::memo(
                Utxo::default(),
                memo_output,
                0,
                Some(coin_value),
            ));
            // create output coin
            let coin_out = twilight_client_sdk::util::create_output_coin_for_trader(
                coin_address.clone(),
                161341791u64,
                Scalar::from(100000u64),
            )
            .unwrap();
            let path = "../zkos-client-wallet/relayerprogram.json";
            let programs =
                twilight_client_sdk::programcontroller::ContractManager::import_program(path);
            let script_address = programs.create_contract_address(Network::Mainnet).unwrap();
            let settle_program = programs.get_program_by_tag("SettleTraderOrder").unwrap();
            //create output state
            let tvl_1: Commitment = Commitment::blinded(10099754920u64);
            let tps_1: Commitment = Commitment::blinded(10u64);
            let s_var: ZString = ZString::from(tps_1.clone());
            let s_var_vec: Vec<ZString> = vec![s_var];
            // create Output state
            let out_state: OutputState = OutputState {
                nonce: 2,
                script_address: script_address.clone(),
                owner: coin_address.clone(),
                commitment: tvl_1,
                state_variables: Some(s_var_vec),
                timebounds: 0,
            };

            let output: Vec<Output> = vec![coin_out, Output::state(OutputData::State(out_state))];
            // create Input State
            let tvl_0: Commitment = Commitment::blinded(10107699102u64);
            let tps_0: Commitment = Commitment::blinded(10u64);
            let s_var: ZString = ZString::from(tps_0.clone());
            let in_state_var_vec: Vec<ZString> = vec![s_var];
            let temp_out_state = OutputState {
                nonce: 1,
                script_address: script_address,
                owner: coin_address.clone(),
                commitment: tvl_0.clone(),
                state_variables: Some(in_state_var_vec),
                timebounds: 0,
            };
            //1093992493500
            let margin_difference = Commitment::blinded(234730u64);
            let error_int = -zkvm::ScalarWitness::Integer(896328182u64.into());
            let error_scalar: Scalar = error_int.into();
            let pay_string: Vec<ZString> = vec![
                ZString::from(margin_difference),
                ZString::from(error_scalar),
            ];
            // convert to input
            let input_state: Input = Input::state(InputData::state(
                Utxo::default(),
                temp_out_state.clone(),
                Some(pay_string),
                1,
            ));
            let input: Vec<Input> = vec![memo_in, input_state];
            //tx_date i.e., settle price
            let tx_data: zkvm::String = zkvm::String::from(Scalar::from(52129u64));

            //cretae unsigned Tx with program proof
            let result = transaction::vm_run::Prover::build_proof(
                settle_program,
                &input,
                &output,
                false,
                Some(tx_data.clone()),
            );
            log::debug!("{:?}", result);
            let (prog_bytes, proof) = result.unwrap();
            let verify = transaction::vm_run::Verifier::verify_r1cs_proof(
                &proof,
                &prog_bytes,
                &input,
                &output,
                false,
                Some(tx_data),
            );
            log::debug!("{:?}", verify);

            //println!("Scalar {:?}", Scalar::from(875599u64));
        }
        #[test]
        fn test_liquidate_order() {
            // create the input state based on the previous Output State and additional script data

            //create InputMemo and OutputCoin
            let mut rng = rand::thread_rng();
            let sk: quisquislib::ristretto::RistrettoSecretKey = SecretKey::random(&mut rng);
            let pk = RistrettoPublicKey::from_secret_key(&sk, &mut rng);
            let commitment_scalar = Scalar::random(&mut rng);
            let commit =
                ElGamalCommitment::generate_commitment(&pk, commitment_scalar, Scalar::from(0u64));
            let add: Address = Address::standard_address(Network::default(), pk.clone());
            let out_coin = OutputCoin {
                encrypt: commit,
                owner: add.as_hex(),
            };
            let coin_out: Output = Output::coin(OutputData::coin(out_coin));

            // *****  InputMemo  *********/
            // ****************************/
            let script_address =
                Address::script_address(Network::Mainnet, *Scalar::random(&mut rng).as_bytes());
            //IM
            let commit_memo = Commitment::blinded_with_factor(500u64, commitment_scalar.clone());
            //Leverage committed
            let leverage = Commitment::blinded(5u64);
            // entryprice in cents
            let entry_price = 43000u64;
            // PositionSize
            let position_size = 125000u64;
            let order_side: u64 = 1u64;
            let data: Vec<ZString> = vec![
                ZString::from(Scalar::from(position_size)),
                ZString::from(leverage),
                ZString::from(Scalar::from(entry_price)),
                ZString::from(Scalar::from(order_side)),
            ];
            let memo_out = OutputMemo {
                script_address: script_address.as_hex(),
                owner: add.as_hex(),
                commitment: commit_memo,
                data: Some(data),
                timebounds: 0,
            };
            let coin_value: Commitment = Commitment::blinded(0u64); //(82u64); // AM to be pushed back to the user
            let memo_in = Input::memo(InputData::memo(
                Utxo::default(),
                memo_out,
                0,
                Some(coin_value),
            ));
            let path = "../zkos-client-wallet/relayerprogram.json";
            let programs =
                twilight_client_sdk::programcontroller::ContractManager::import_program(path);
            let script_address = programs.create_contract_address(Network::Mainnet).unwrap();
            let settle_program = programs.get_program_by_tag("LiquidateOrder").unwrap();
            //create output state
            let tvl_1: Commitment = Commitment::blinded(10500u64);
            let tps_1: Commitment = Commitment::blinded(10u64);
            let s_var: ZString = ZString::from(tps_1.clone());
            let s_var_vec: Vec<ZString> = vec![s_var];
            // create Output state
            let out_state: OutputState = OutputState {
                nonce: 2,
                script_address: script_address.clone(),
                owner: add.as_hex(),
                commitment: tvl_1,
                state_variables: Some(s_var_vec),
                timebounds: 0,
            };

            let output: Vec<Output> = vec![coin_out, Output::state(OutputData::State(out_state))];

            // create Input State
            let tvl_0: Commitment = Commitment::blinded(12000u64);
            let tps_0: Commitment = Commitment::blinded(10u64);
            let s_var: ZString = ZString::from(tps_0.clone());
            let in_state_var_vec: Vec<ZString> = vec![s_var];
            let temp_out_state = OutputState {
                nonce: 1,
                script_address,
                owner: add.as_hex(),
                commitment: tvl_0.clone(),
                state_variables: Some(in_state_var_vec),
                timebounds: 0,
            };
            //1093992493500
            let margin_difference = Commitment::blinded(0u64);
            let error_int = -zkvm::ScalarWitness::Integer(0u64.into());
            let error_scalar: Scalar = error_int.into();
            let pay_string: Vec<ZString> = vec![
                ZString::from(margin_difference),
                ZString::from(error_scalar),
            ];
            // convert to input
            let input_state: Input = Input::state(InputData::state(
                Utxo::default(),
                temp_out_state.clone(),
                Some(pay_string),
                1,
            ));
            let input: Vec<Input> = vec![memo_in, input_state];
            //tx_date i.e., settle price
            let tx_data: zkvm::String = zkvm::String::from(Scalar::from(43500u64));

            //cretae unsigned Tx with program proof
            let result = transaction::vm_run::Prover::build_proof(
                settle_program,
                &input,
                &output,
                false,
                Some(tx_data.clone()),
            );
            log::debug!("{:?}", result);
            let (prog_bytes, proof) = result.unwrap();
            let verify = transaction::vm_run::Verifier::verify_r1cs_proof(
                &proof,
                &prog_bytes,
                &input,
                &output,
                false,
                Some(tx_data),
            );
            log::debug!("{:?}", verify);
        }
        #[test]
        fn test_test_tx_hex() {
            let tx_hex = "010000000100000000000000000000000100000000000000000000000000000002020202000000000000000100000001000000a879867a38e022579ce73b76a819a4462c9c31e8a7db2ff0217e45e2f6d127ec002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a00000000000000306365613839626563303530353036376566616530326666656330303734393934376264363662336232396430366263346535323866666562663962613238353230393839343561306538386464323166353130323661373062666362373434653064336566376338643131633563633763373838663436393766323034373137653331653737613961000000003a76281115f6e5419512ac4d69e2d8adf4702b13e607d34d978af7c77f7e2e600104000000000000000300000001000000002a05f5d38e000000000000000000000000000000000000000000000000000002000000000000007695eaf3d3781e657533023b520405f8cff6b71eaa1fe5bf39f434b5e4a5f45a03000000010000007bcc0000000000000000000000000000000000000000000000000000000000000300000001000000ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010000000001600000000000000060a0403000000060a0405000000060a0d0e1302020200000000010000000000000003000000000000003d107ff89a1f0387ca226522f82bca1fbf43059a200c49bdae998400bfe89ea52c92d3c5e02c98dc6b6f1f91cfd42e136d1d4f1de6bdb351b12be20f9535960c7c1b7c42e22f98283d98314b914cdbfc380ef2bb1c3e3a91685a05614fc4cf6da101000000000000002cac2b73b4a4abc5890fc552db1a2bf21f8f1ff689c5b8fca20e7d6ff96a7c079869a8e3dca88a1e587eedbd8ceb774206e76b8edced16c3ae91ec35f801846a4ca486bda374c727d1b62736ae8a6e8e932fa35ddd210c113474cbc3863e120320dcca125f47d0eeeec2b3cdab60acd37a76c66e2a12701a342f4f47226d4e0728e3063c17462a7e9d5c1d403c76e146045e4471078381c78d50709e9b3628215cf3672ccf89e7ade1f4026580750181bbd8e9c9cfe4590710d6fb57d686cc2428fc117b72080ff68996217b310033be720b86812ea0daef7ab4eba15c4e322d6081f383c26a4b475276c9766772876ccb43bc01ee4907e583c3591a55238829be0152422ec69f924132b7212d299990743c5460b9e4d99e0070a0456051370e03c082c1bbb3bffb46c67eebed25df1a27330768f50fc0f068986536c10a610cbd02316c7b5f6d29c822824ece1c8c7f77196a73585e0af25e7a662a0da70c0501dff504e6cca86c8282e6c043343eacd7812675fcee2b94937aaddbecec74008d045402eee1c2431fdc73988c4023ee981cef5c63c54005b77f6a4f9083070c0100000000000000020000004000000000000000a4a57e74978cc5b4ef596d22468d6b8ba49343a88f8e7914cf93c24c4966ee398ac101f1ab6c6e41285fc8e06ada99c66a6b920f0caace28c77530a428222802010000000100000000000000c65d58e4d27b4b22d898eb3d6508df914f0864da3039e941969d55581305a60201000000000000007f0683f1b41dabb3f63ca6ae666383f9b04978ed6cf8c89d476e43b5794e940d0000000000000000e4f239f44b15a9a8621b74a7e79d422b8d463137e91fe98239ffa2b6e384600c0102000000010000000000000040420f00000000000000000000000000741378c7ce2b8087b278de9efe06d44db57c1d45ff826f9c4db08d621f49e903";

            // recreate clientZkos struct
            let client_zkos = twilight_client_sdk::relayer_types::CreateTraderOrderClientZkos::decode_from_hex_string(tx_hex.to_string()).unwrap();
            let order_tx = client_zkos.tx;
            log::debug!("Order Zkos Tx {:?}", order_tx);
            // check the verification function
            let verify = crate::verify_client_message::verify_client_create_trader_order(&order_tx);
            log::debug!("Verify Order Initial TX{:?}", verify);

            // update the tx with the new entry price and position sizze
            let entry_price = 50687u64;
            let position_size = 100000 * 10 * entry_price;
            let updated_tx = crate::order::update_memo_tx_client_order(
                &order_tx,
                entry_price,
                position_size,
                100,
            )
            .unwrap();
            let tx_new = updated_tx.get_tx();
            log::debug!("New Zkos Tx Updated{:?}", tx_new);
            let updated_memo = updated_tx.get_output();
            log::debug!("{:?}", updated_memo);
            // check the verification function
            let verify = crate::verify_client_message::verify_client_create_trader_order(&tx_new);
            log::debug!("Verify New Order{:?}", verify);
        }
    }
}
