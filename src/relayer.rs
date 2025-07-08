//! Entry point to all operations supported by relayer

use quisquislib::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use twilight_client_sdk::*;

/// Initialize the relayer wallet with the given password, seed and path.
/// @param password: password used to encrypt the private key. [16 bytes]
/// @param iv_encryption_str: initialization vector used to encrypt the private key. [16 bytes]
/// @param seed: Keplr/Metamask signature seed used to generate the private key.
/// @param path: path to the file where the private key is stored.
pub fn initialize_relayer_wallet(
    password: String,
    iv_encryption_str: String,
    seed: String,
    path: String,
) -> Option<RistrettoSecretKey> {
    twilight_client_sdk::keys_management::init_wallet(
        password.as_bytes(),
        iv_encryption_str,
        seed.as_bytes(),
        Some(path),
    )
}

/// Load existing wallet
/// @param password: password used to encrypt the private key.
/// @param iv_encryption_str: initialization vector used to encrypt the private key.
/// @param path: path to the file where the private key is stored.
/// @return: RistrettoSecretKey
pub fn load_relayer_wallet(
    password: String,
    iv_encryption_str: String,
    path: String,
) -> Option<RistrettoSecretKey> {
    twilight_client_sdk::keys_management::load_wallet(
        password.as_bytes(),
        path,
        iv_encryption_str.as_bytes(),
    )
}

/// Load public key from existing walller
/// @param secret_key: RistrettoSecretKey
/// @param path: path to the file where the public key is stored.
/// @return: RistrettoPublicKey
///
pub fn load_public_key(secret_key: RistrettoSecretKey, path: String) -> RistrettoPublicKey {
    twilight_client_sdk::keys_management::get_public_key(secret_key, path)
}

/// create public key and save it on file
/// @param secret_key: RistrettoSecretKey
/// @param path: path to the file where the public key is stored.
/// @return: RistrettoPublicKey
///
pub fn get_public_key(secret_key: RistrettoSecretKey, path: String) -> RistrettoPublicKey {
    twilight_client_sdk::keys_management::get_public_key(secret_key, path)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    pub fn test_relayer_wallet_test() {
        let password = b"your_password_he";
        let iv = b"your_password_he"; // Use a secure way to handle the password
        let seed =
     "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
        let wallet = twilight_client_sdk::keys_management::init_wallet(
            password,
            "wallet.txt".to_string(),
            iv,
            Some(seed.to_string()),
        );
        println!("wallet {:?}", wallet);
    }

    // cargo test -- --nocapture --test test_get_Wallet_key_test --test-threads 5
    #[test]
    pub fn test_get_Wallet_key_test() {
        let wallet = load_relayer_wallet(
            "your_password_he".to_string(),
            "your_password_he".to_string(),
            "./wallet.txt".to_string(),
        );

        println!("wallet {:?}", wallet);
        // let contract_owner_sk = wallet.unwrap();
    }
}
