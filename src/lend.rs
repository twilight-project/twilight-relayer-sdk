//! Create and Broadcast a Lend Order and Settlement Transaction
//! Creates a ScriptTransaction

use address::Network;
use quisquislib::ristretto::RistrettoSecretKey;
use transaction::{ScriptTransaction, Transaction};
use twilight_client_sdk::programcontroller::ContractManager;
use zkschnorr::Signature;
//use merlin::Transcript;
use quisquislib::{accounts::prover::SigmaProof, ristretto::RistrettoPublicKey};
use zkvm::zkos_types::StateWitness;
use zkvm::{
    zkos_types::{Input, Output, ValueWitness},
    Commitment, String as ZkvmString, Witness,
};

use crate::SignedInteger;

///Updates the OutputMemo to reflect the latest open order proce for client
/// This function is called by the relayer
/// @param memo : Input Memo received from the client
/// @param pool_share : Poolshare to be updated
/// @return output_memo : Output Memo created by the relayer
pub fn update_lender_output_memo(memo: Output, pool_share: u64) -> Result<Output, &'static str> {
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
    // extract blinding scalar from data to reuse it to commit new poolshare value
    let data_commitment = match data[0].clone().to_commitment() {
        Ok(commitment) => commitment,
        Err(_) => return Err("Error in getting the commitment from the data")?,
    };
    // extract scalar blinding from the commitment
    let scalar_witness = match data_commitment.witness() {
        Some(witness) => witness,
        None => return Err("Error in getting the witness from the commitment")?,
    };
    let blinding = scalar_witness.1;
    // create new commitment for the poolshare
    let new_commitment = Commitment::blinded_with_factor(pool_share, blinding);
    //update poolshare
    data[0] = zkvm::String::Commitment(Box::new(new_commitment));
    // update the output memo
    output_memo.set_data(data.clone());
    Ok(output_memo.to_output())
}
/// create input state for the Lend Order
/// Utxo Id is fetched from the chain using the contract owner address
///
pub fn create_input_state_for_lend_order(
    contract_owner_addresss: String,
    out_state: Output,
    error: i128,
) -> Result<Input, String> {
    // create SignedInteger
    let signed_integer = SignedInteger::from(error);
    // convert the error to ZKVM String
    let error_scalar = signed_integer.to_scalar();
    let script_data = vec![ZkvmString::from(error_scalar)];
    // call the client wallet function to create input state
    twilight_client_sdk::chain::get_transaction_state_input_from_address(
        contract_owner_addresss,
        out_state,
        Some(script_data),
    )
}
/// Creates the ScriptTransaction for creating the Lend order on relayer for chain
///
/*******  Inputs *******/
/// @param input_coin :  Input received from the Lender
/// @param output_memo : Output Memo created by the Lender
/// @param signature : Signature over the input_coin as Verifier view sent by the Lender
/// @param proof : Sigma proof of same value committed in Coin and Memo sent by the Lender
/// @param contract_manager : Contract Manager for the Programs
/// @param chain_network : Network for the chain
/// @param fee : Fee to be paid to the chain
/// @address : Address of the Contract State Owner
/// @return : Transaction containing ScriptTransaction
/// @return : Output containing State updated to be reused by the relayer later
#[allow(clippy::too_many_arguments)]
///
pub fn create_lend_order_transaction(
    input_coin: Input,          // Input Coin received from the Lender
    output_memo: Output,        // Output Memo created by the Lender
    input_state_output: Output, // Output State to be used as Input State for this tx
    output_state: Output,       // Output State for this tx
    signature: Signature,       // Signature over the input_coin as Verifier view sent by the Lender
    proof: SigmaProof, // Sigma proof of same value committed in Coin and Memo sent by the Lender
    contract_manager: &ContractManager,
    chain_network: Network,
    fee: u64,                       // in satoshis
    contract_owner_address: String, // Address of the Contract State Owner
    error: i128,                    // Error required for program execution
    sk: RistrettoSecretKey,         // Secret key of the Contract State Owner
    pk: RistrettoPublicKey,         // Public key of the Contract State Owner
) -> Result<Transaction, String> {
    //create Value witness as the witness for coin input
    let value_witness =
        Witness::ValueWitness(ValueWitness::set_value_witness(signature, proof.clone()));

    // create the input state
    let input_state = create_input_state_for_lend_order(
        contract_owner_address.clone(),
        input_state_output,
        error,
    )?;

    let inputs = vec![input_coin.clone(), input_state.clone()];
    let outputs = vec![output_memo, output_state.clone()];

    // get the program from the contract manager
    let order_tag = "CreateLendOrder";
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
        Err(_) => return Err("Error in creating program proof")?,
    };

    // create witness for the State input and output
    let state_witness = Witness::State(StateWitness::create_state_witness(
        &input_state,
        &output_state,
        sk,
        pk,
        false,
    ));

    // create witness vector
    let witness_vec = vec![value_witness, state_witness];

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
/// creates the lend order settlement transaction
/// Client send a Memo Output with the settlement request
/// relayer creats the Input Memo and Output Coin
/// relayer creates the Input State and Output State
///
#[allow(clippy::too_many_arguments)]
pub fn create_lend_order_settlement_transaction(
    client_output_memo: Output, // Memo Output sent by the client (C(Deposit), Poolshare)
    payment: u64,               // amount to be paid to the client
    contract_manager: &ContractManager,
    chain_network: Network,
    fee: u64,                       // in satoshis
    contract_owner_address: String, // Address of the CONTRACT State Owner
    input_state_output: Output,     // Output State to be used as Input State for this tx
    output_state: Output,           // Output State for this tx
    error: i128,
    sk: RistrettoSecretKey, // Secret key of the CONTRACT State Owner
    pk: RistrettoPublicKey, // Public key of the CONTRACT State Owner
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

    // create the input state
    let input_state = create_input_state_for_lend_order(
        contract_owner_address.clone(),
        input_state_output,
        error,
    )?;

    // create witness for the State input and output
    let state_witness = Witness::State(StateWitness::create_state_witness(
        &input_state,
        &output_state,
        sk,
        pk,
        false,
    ));

    // create witness vector
    let witness_vec = vec![memo_witness, state_witness];
    // get the program from the contract manager
    let program_tag = "SettleLendOrder";
    let lend_settle_program = match contract_manager.get_program_by_tag(program_tag) {
        Ok(program) => program,
        Err(_) => return Err("Error in getting the program from the contract manager")?,
    };
    // create callproof for the program
    let call_proof = contract_manager.create_call_proof(chain_network, program_tag)?;

    let inputs = vec![input_memo.clone(), input_state.clone()];
    let outputs = vec![output_coin.clone(), output_state.clone()];

    // execute the program and create a proof for computations
    let program_proof = transaction::vm_run::Prover::build_proof(
        lend_settle_program.clone(),
        &inputs,
        &outputs,
        false,
        None,
    );

    let (program, proof) = match program_proof {
        Ok((program, proof)) => (program, proof),
        Err(_) => return Err("Error in creating program proof")?,
    };
    // converts inputs and outputs to hide the encrypted data using verifier view and update witness index
    let (inputs, outputs, _) = ScriptTransaction::create_verifier_view(&inputs, &outputs, None);
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

        use crate::order;

        use super::*;
        #[test]
        fn test_lend_order_deposit_program() {
            //create InputCoin and OutputMemo
            dotenvy::dotenv().expect("Failed loading dotenv");
            let seed = std::env::var("TEST_SEED")
                .unwrap_or_else(|_| "generate_random_test_seed".to_string());

            //derive private key;
            //derive private key;
            let sk = SecretKey::from_bytes(seed.as_bytes());
            let client_address = "0ca23f1c0a63094958b6a90a10c3600de026e54ef0eecce9dc11379b14236f036ba45c75072a6732b057cb667d6a11caecb86bea35a959d28bfd1cfac2c6442f52c3a5d50e";

            let input_coin = twilight_client_sdk::chain::get_transaction_coin_input_from_address(
                client_address.to_string(),
            )
            .unwrap();

            let scalar_hex = "109a0657ac087f9e5819f8783e0dc1b1f93c749bd78d8938db553ebaca1d6c0b";
            let rscalar = twilight_client_sdk::util::hex_to_scalar(scalar_hex.to_string()).unwrap();
            let deposit = 15000u64;
            let pool_share = 1u64;

            let path = "../zkos-client-wallet/relayerprogram.json";
            let programs =
                twilight_client_sdk::programcontroller::ContractManager::import_program(path);
            let contract_address = programs
                .create_contract_address(Network::default())
                .unwrap();
            let output_memo = twilight_client_sdk::util::create_output_memo_for_lender(
                contract_address.clone(),
                client_address.to_string(),
                deposit,
                pool_share,
                rscalar,
                0u32,
            );
            // create value witness
            let zkos_order_str = twilight_client_sdk::relayer::create_lend_order_zkos(
                input_coin.clone(),
                output_memo.clone(),
                sk,
                scalar_hex.to_string(),
                deposit,
                "account_id".to_string(),
                deposit as f64,
                "LEND".to_string(),
                "PENDING".to_string(),
                deposit as f64,
            )
            .unwrap();
            // get signature and proof
            let lend_order =
                twilight_client_sdk::relayer_types::CreateLendOrderZkos::decode_from_hex_string(
                    zkos_order_str.clone(),
                )
                .unwrap();
            let sign = lend_order.input.signature;
            let proof = lend_order.input.proof;

            let old_state_hex = "0200000002000000020000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a000000000000003063633632366165313065393032356431303439353061616663666164636365336462303536313561333663643931663262383562626630306266643637336133383530306562666337346663316166396165323564326639623337383930346635386564383239356235313365343030616465633635316234346661616537363935623462626334350100000000000000abcd9a3b0000000000000000000000006c5edc68891d2d23d53250923ec2bacf936fe441f33a197c0e092bd91f34f301010100000000000000020000000100000000000000a08601000000000000000000000000008bf1fe9599f3c42b6d196f352ed1eaf1ca67ff403272a138dabfaeb7780d430c00000000";
            let old_state_bytes = hex::decode(old_state_hex).unwrap();
            let old_state: Output = bincode::deserialize(&old_state_bytes).unwrap();
            let error: i128 = -499999061;
            let state_owner_address = "0cc626ae10e9025d104950aafcfadcce3db05615a36cd91f2b85bbf00bfd673a38500ebfc74fc1af9ae25d2f9b378904f58ed8295b513e400adec651b44faae7695b4bbc45".to_string();
            // get pk of the state owner

            let address =
                Address::from_hex(&state_owner_address, address::AddressType::default()).unwrap();
            let state_owner_pk: RistrettoPublicKey = address.into();
            let output_state = twilight_client_sdk::util::create_output_state_for_trade_lend_order(
                3,
                contract_address,
                state_owner_address.clone(),
                1000015939u64,
                100001u64,
                0,
            );

            let lend_tx = crate::lend::create_lend_order_transaction(
                input_coin.clone(),
                output_memo.clone(),
                old_state,
                output_state,
                sign,
                proof,
                &programs,
                Network::default(),
                10u64,
                state_owner_address,
                error,
                sk,
                state_owner_pk,
            )
            .unwrap();
            let verify = lend_tx.verify();
            println!("{:?}", verify);
        }
        #[test]
        fn test_create_lend_order_chain_data() {}
        //#[test]
        //     fn test_lend_settle_order_stack() {
        //         let correct_program = self::lend_order_settle_program();
        //         println!("\n Program \n{:?}", correct_program);

        //         //create InputMemo and OutputCoin

        //         let mut rng = rand::thread_rng();
        //         let sk_in: quisquislib::ristretto::RistrettoSecretKey = SecretKey::random(&mut rng);
        //         let pk_in = RistrettoPublicKey::from_secret_key(&sk_in, &mut rng);
        //         let commit_in = ElGamalCommitment::generate_commitment(
        //             &pk_in,
        //             Scalar::random(&mut rng),
        //             Scalar::from(219u64),
        //         );
        //         let add: Address = Address::standard_address(Network::default(), pk_in.clone());
        //         let out_coin = OutputCoin {
        //             encrypt: commit_in,
        //             owner: add.as_hex(),
        //         };
        //         let coin_out: Output = Output::coin(OutputData::coin(out_coin));

        //         //*****  InputMemo  *********/
        //         //****************************/
        //         let script_address =
        //             Address::script_address(Network::Mainnet, *Scalar::random(&mut rng).as_bytes());
        //         // Initial Deposit
        //         let commit_memo = Commitment::blinded(300u64);
        //         //Poolsize committed
        //         let pool_share = Commitment::blinded(245u64);

        //         let data: Vec<ZString> = vec![ZString::from(pool_share)];
        //         let memo_out = OutputMemo {
        //             script_address: script_address.as_hex(),
        //             owner: add.as_hex(),
        //             commitment: commit_memo,
        //             data: Some(data),
        //             timebounds: 0,
        //         };
        //         let withdraw: Commitment = Commitment::blinded(33u64); // Withdraw to be pushed back to the user
        //         let memo_in = Input::memo(InputData::memo(
        //             Utxo::default(),
        //             memo_out,
        //             0,
        //             Some(withdraw),
        //         ));

        //         //create output state
        //         let tvl_1: Commitment = Commitment::blinded(3194u64);
        //         let tps_1: Commitment = Commitment::blinded(23030u64);
        //         let s_var: ZString = ZString::from(tps_1.clone());
        //         let s_var_vec: Vec<ZString> = vec![s_var];
        //         // create Output state
        //         let out_state: OutputState = OutputState {
        //             nonce: 2,
        //             script_address: script_address.as_hex(),
        //             owner: add.as_hex(),
        //             commitment: tvl_1,
        //             state_variables: Some(s_var_vec),
        //             timebounds: 0,
        //         };

        //         let output: Vec<Output> = vec![coin_out, Output::state(OutputData::State(out_state))];
        //         // create Input State
        //         let tvl_0: Commitment = Commitment::blinded(3227u64);
        //         let tps_0: Commitment = Commitment::blinded(23275u64);
        //         let s_var: ZString = ZString::from(tps_0.clone());
        //         let in_state_var_vec: Vec<ZString> = vec![s_var];
        //         let temp_out_state = OutputState {
        //             nonce: 1,
        //             script_address: script_address.as_hex(),
        //             owner: add.as_hex(),
        //             commitment: tvl_0.clone(),
        //             state_variables: Some(in_state_var_vec),
        //             timebounds: 0,
        //         };
        //         let error_int = -zkvm::ScalarWitness::Integer(22540u64.into());
        //         let error_scalar: Scalar = error_int.into();
        //         let pay_string: Vec<ZString> = vec![ZString::from(error_scalar)];
        //         // convert to input
        //         let input_state: Input = Input::state(InputData::state(
        //             Utxo::default(),
        //             temp_out_state.clone(),
        //             Some(pay_string),
        //             1,
        //         ));
        //         let input: Vec<Input> = vec![memo_in, input_state];

        //         //cretae unsigned Tx with program proof
        //         let result = Prover::build_proof(correct_program, &input, &output, false, None);
        //         println!("{:?}", result);
        //         let (prog_bytes, proof) = result.unwrap();
        //         let verify = Verifier::verify_r1cs_proof(&proof, &prog_bytes, &input, &output, false, None);
        //         println!("{:?}", verify);
        //     }

        #[test]
        fn test_decode_state_hex() {
            let state_hex = "0200000002000000030000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a00000000000000306363363236616531306539303235643130343935306161666366616463636533646230353631356133366364393166326238356262663030626664363733613338353030656266633734666331616639616532356432663962333738393034663538656438323935623531336534303061646563363531623434666161653736393562346262633435010000000000000043089b3b000000000000000000000000e636420871643c0d6c6fd07b284b3b913cd3fd2ab51ffe7dcde4a4c2a99e7903010100000000000000020000000100000000000000a186010000000000000000000000000054e646d07383f9630cb162ad61ee390eefb93ddbfd7b32d3aa84d77c7b0d540d00000000";
            let state_bytes = hex::decode(state_hex).unwrap();
            let state: Output = bincode::deserialize(&state_bytes).unwrap();
            println!("{:?}", state);
        }
    }
}
