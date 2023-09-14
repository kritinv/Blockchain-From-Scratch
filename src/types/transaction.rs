use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature};
use rand::Rng;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
    sender: String,
    receiver: String,
    value: i64,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SignedTransaction {
    transaction: Transaction,
    signature: Vec<u8>,
    public_key: Vec<u8>,
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    let bytes_to_sign: &[u8] = &bincode::serialize(t).unwrap();
    key.sign(&bytes_to_sign)
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &Transaction, public_key: &[u8], signature: &[u8]) -> bool {
    let message = bincode::serialize(t).unwrap(); // Serialize the transaction
    let peer_public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);
    peer_public_key.verify(message.as_ref(), signature).is_ok()
}

#[cfg(any(test, test_utilities))]
pub fn generate_random_transaction() -> Transaction {
    let mut rng = rand::thread_rng();
    let sender = format!("Sender{}", rng.gen::<u32>());
    let receiver = format!("Receiver{}", rng.gen::<u32>());
    let value = rng.gen::<i64>();

    Transaction {
        sender,
        receiver,
        value,
    }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. BEFORE TEST

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::key_pair;
    use ring::signature::KeyPair;


    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, key.public_key().as_ref(), signature.as_ref()));
    }
    #[test]
    fn sign_verify_two() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        let key_2 = key_pair::random();
        let t_2 = generate_random_transaction();
        assert!(!verify(&t_2, key.public_key().as_ref(), signature.as_ref()));
        assert!(!verify(&t, key_2.public_key().as_ref(), signature.as_ref()));
    }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. AFTER TEST