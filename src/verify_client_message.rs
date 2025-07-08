#![allow(non_snake_case)]
//#![deny(missing_docs)]
//! Verifies the requests recived from client
//!

use address::{Address, AddressType};
use curve25519_dalek::ristretto::CompressedRistretto;
use transaction::Transaction;
use twilight_client_sdk::relayer_types::{ZkosCreateOrder, ZkosQueryMsg, ZkosSettleMsg};
use zkschnorr::Signature;
//use merlin::Transcript;
use quisquislib::{
    accounts::prover::SigmaProof,
    // accounts::verifier::Verifier,
    accounts::Account,
    keys::PublicKey,
    ristretto::RistrettoPublicKey,
};

use zkvm::zkos_types::{Input, Output, ValueWitness};

///Verifies the create_trade_order or create_lend_order
/// @param Input = Coin Input carrying the ZkosAccount
/// @param Output = Memo with the order details
/// @param Signature = Signature over input as Verifier view
/// @param proof = Sigma proof of same value committed in Coin and Memo
///
pub fn verify_trade_lend_order(zkos_create_order: &ZkosCreateOrder) -> Result<bool, &'static str> {
    let input: Input = zkos_create_order.input.clone();
    let output: Output = zkos_create_order.output.clone();
    let signature: Signature = zkos_create_order.signature;
    let proof: SigmaProof = zkos_create_order.proof.clone();

    //check owner address on Coin and Memo are same
    // get input owner address

    let input_owner_address = match input.as_owner_address() {
        Some(address) => address,
        None => return Err("Input is not a Coin"),
    };
    // get output owner address
    let output_owner_address = match output.as_output_data().get_owner_address() {
        Some(address) => address,
        None => return Err("Output is not a Memo"),
    };
    // check if owner address on Coin and Memo are same
    if !input_owner_address.eq(output_owner_address) {
        return Err("Owner address on Coin and Memo are different");
    }
    //extract publickey from owner address of input coin
    let coin_owner_address: Address =
        Address::from_hex(input_owner_address, AddressType::Standard)?;
    let pk: RistrettoPublicKey = coin_owner_address.into();

    //create the Verifier View of the Coin and set the Witness to 0
    let input_sign = input.as_input_for_signing();

    //get Pk from input owner address and create account
    let encryption = match input.as_encryption() {
        Some(enc) => enc,
        None => return Err("Input is not a Coin"),
    };
    let enc_acc: Account = Account::set_account(pk, encryption);

    //get verifier view from the output memo
    //let memo_verifier = output.to_verifier_view();

    //extract the commitment value from the memo
    let commitment: CompressedRistretto = output
        .as_output_data()
        .get_commitment()
        .unwrap()
        .to_owned()
        .to_point();

    // verify the Signature over input and Same value Sigma Proof
    let value_witness = ValueWitness::set_value_witness(signature, proof.clone());

    value_witness.verify_value_witness(input_sign, /*memo_verifier,*/ pk, enc_acc, commitment)
}

///Verifies the create_trader_order msg sent from the client
/// @param tx = script tx carrying the program and the proof and all information relating to the order
/// @return bool: returns true iif verified otherwise false
///
pub fn verify_client_create_trader_order(order_tx: &Transaction) -> Result<bool, &'static str> {
    // verify tx
    match order_tx.verify() {
        Ok(_) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Verifies the settlement request for Trader or lend order
/// @param Output = Memo carrying the initial order details as Prover view
/// @param Signature = Signature over the output as Prover view
///
pub fn verify_settle_requests(zkossettlemsg: &ZkosSettleMsg) -> Result<(), &'static str> {
    let output_memo: Output = zkossettlemsg.output.clone();
    let signature: Signature = zkossettlemsg.signature;
    // let output_memo_verifier = output_memo.to_verifier_view();
    //extract publickey from owner address of output memo
    let owner_address_str = match output_memo.as_output_data().get_owner_address() {
        Some(address) => address,
        None => return Err("SettleVerification Failed: Output has no owner address"),
    };
    let owner_address: Address = Address::from_hex(owner_address_str, AddressType::Standard)?;
    let pk: RistrettoPublicKey = owner_address.into();

    // verify the signature over the output memo

    //serialize the output for sign verification
    let message = match bincode::serialize(&output_memo) {
        Ok(message) => message,
        Err(_) => return Err("SettleVerification Failed: Input serialization failed"),
    };
    pk.verify_msg(&message, &signature, ("PublicKeySign").as_bytes())
}

/// Verifies the query request for Trader or lend order
/// Verifies the cancel order request
/// @param address = Hex Address string of the trader or lender zkosAccount used for creating the order
/// @param signature = Signature over the standard request (QueryTraderOrder/ QueryLendOrder/ CancelTraderOrder)
/// @param message = Message used for signing the query request. Bincode Serialized (QueryTraderOrder/ QueryLendOrder /CancelTraderOrder) type
/// relayer should serialize the query message before passing it to the function
///
pub fn verify_query_order(
    zkos_query_msg: ZkosQueryMsg,
    message: &[u8],
) -> Result<(), &'static str> {
    let owner_address = zkos_query_msg.public_key;
    let signature = zkos_query_msg.signature;
    //extract Address from hex
    let coin_owner_address = Address::from_hex(&owner_address, AddressType::default())?;
    //extract the public key from address
    let pk: RistrettoPublicKey = coin_owner_address.into();
    //verify the signature
    pk.verify_msg(message, &signature, ("PublicKeySign").as_bytes())
}

//
// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------
#[cfg(test)]
mod test {
    use super::*;
    use address::Network;
    use curve25519_dalek::scalar::Scalar;
    use quisquislib::elgamal::ElGamalCommitment;
    use quisquislib::keys::SecretKey;
    use rand::rngs::OsRng;
    use zkvm::zkos_types::{
        IOType, Input, InputData, Output, OutputCoin, OutputData, OutputMemo, OutputState,
    };
    use zkvm::{Commitment, Utxo};
    #[test]
    fn test_verify_query_order() {
        let (acc, prv) = Account::generate_random_account_with_value(Scalar::from(20u64));
        let (pk, _enc) = acc.get_account();
        let message = ("0a000000000000006163636f756e745f6964040000008c0000000000000022306366363661623465306432373239626538373835333366376663313866336364313862316337383764396230336262343163303263326235316561353239373437326330633433323934646131653035643736353235633234393336383234303636356565353632353363656435333466656362616536313437336130343737663631613866616634224000000000000000180bdfbb82e758e70684c3125b011a10b2205db929867c7507e3b156ff96be2f6a2aaeb522576b54743fdf5f10bc7ecb88328d15d35c98a2b0512b60fc0da405").as_bytes();
        let signature: Signature = pk.sign_msg(&message, &prv, ("PublicKeySign").as_bytes());
        //Verification
        let address: Address = Address::standard_address(address::Network::default(), pk.clone());
        let add_hex: String = address.as_hex();
        let zkos_query_msg = ZkosQueryMsg {
            public_key: add_hex,
            signature,
        };
        let verify_query = verify_query_order(zkos_query_msg, &message);
        println!("verify_query: {:?}", verify_query);
        assert!(verify_query.is_ok());
    }

    #[test]
    fn Test_verify_settle_requests() {
        let (acc, prv) = Account::generate_random_account_with_value(Scalar::from(20u64));
        let (pk, _enc) = acc.get_account();
        let message = ("0a000000000000006163636f756e745f6964040000008c0000000000000022306366363661623465306432373239626538373835333366376663313866336364313862316337383764396230336262343163303263326235316561353239373437326330633433323934646131653035643736353235633234393336383234303636356565353632353363656435333466656362616536313437336130343737663631613866616634224000000000000000180bdfbb82e758e70684c3125b011a10b2205db929867c7507e3b156ff96be2f6a2aaeb522576b54743fdf5f10bc7ecb88328d15d35c98a2b0512b60fc0da405").as_bytes();
        let signature: Signature = pk.sign_msg(&message, &prv, ("PublicKeySign").as_bytes());
        //Verification
        let address: Address = Address::standard_address(Network::default(), pk.clone());
        let add_hex: String = address.as_hex();
        let zkos_query_msg = ZkosQueryMsg {
            public_key: add_hex,
            signature,
        };
        let verify_query = verify_query_order(zkos_query_msg, &message);
        println!("verify_query: {:?}", verify_query);
        assert!(verify_query.is_ok());
    }

    #[test]
    fn test_verify_trade_lend_order() {
        //create the input coin
        let mut rng = rand::thread_rng();
        let sk: quisquislib::ristretto::RistrettoSecretKey = SecretKey::random(&mut rng);
        let pk = RistrettoPublicKey::from_secret_key(&sk, &mut rng);
        let comm_scalar = Scalar::random(&mut OsRng);
        let enc =
            ElGamalCommitment::generate_commitment(&pk, comm_scalar.clone(), Scalar::from(20u64));

        let address: Address = Address::standard_address(Network::default(), pk.clone());
        let add_hex: String = address.as_hex();

        let coin = OutputCoin::new(enc.clone(), add_hex.clone());
        let utxo: Utxo = Utxo::default();
        let coin_input = Input::coin(InputData::coin(utxo, coin, 0));

        //create the output memo for the input coin
        let commit = Commitment::blinded_with_factor(20u64, comm_scalar.clone());

        let out_memo: OutputMemo =
            OutputMemo::new(add_hex.clone(), add_hex.clone(), commit, None, 0);
        let output = Output::memo(OutputData::memo(out_memo.clone()));
        let enc_acc = Account::set_account(pk.clone(), enc.clone());
        let out_memo_verifier = out_memo.verifier_view();
        let input_sign = coin_input.as_input_for_signing();
        //Verification
        let witness = ValueWitness::create_value_witness(
            input_sign.clone(),
            sk,
            // output.clone(),
            enc_acc,
            pk.clone(),
            out_memo_verifier.commitment.into(),
            20u64,
            comm_scalar.clone(),
        );

        //Verification

        let signature = witness.get_signature().to_owned();
        let proof = witness.get_value_proof().to_owned();
        let create_order_zkso = ZkosCreateOrder {
            input: coin_input,
            output,
            signature,
            proof,
        };

        let verify_query = verify_trade_lend_order(&create_order_zkso);
        println!("verify_query: {:?}", verify_query);
        assert!(verify_query.is_ok());
    }
    //     use crate::vm_run::{Prover, Verifier};
}
