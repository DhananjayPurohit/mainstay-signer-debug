use bip32::{ExtendedPrivateKey, ExtendedKeyAttrs, DerivationPath, ChildNumber, PublicKey};
use bip32;
use hex::{encode, decode};
use secp256k1;
use serde_json::from_str;
use serde_json::Value;
use btc_transaction_utils::UnspentTxOutValue;
use btc_transaction_utils::p2wsh::InputSigner;
use btc_transaction_utils::multisig::RedeemScript;
use bitcoin;
use std::str::FromStr;

const TX_DATA_RES: &str = r#"
{
    "txid": "b891111d35ffc72709140b7bd2a82fde20deca53831f42a96704dede42c793d2",
    "hash": "b891111d35ffc72709140b7bd2a82fde20deca53831f42a96704dede42c793d2",
    "version": 2,
    "size": 194,
    "vsize": 194,
    "weight": 776,
    "locktime": 0,
    "vin": [
      {
        "txid": "047352f01e5e3f8adc04a797311dde3917f274e55ceafb78edc39ff5d87d16c5",
        "vout": 0,
        "scriptSig": {
          "asm": "0 30440220049d3138f841b63e96725cb9e86a53a92cd1d9e1b0740f5d4cd2ae0bcab684bf0220208d555c7e24e4c01cf67dfa9161091533e9efd6d1602bb53a49f7195c16b037[ALL] 5121036bd7943325ed9c9e1a44d98a8b5759c4bf4807df4312810ed5fc09dfb967811951ae",
          "hex": "004730440220049d3138f841b63e96725cb9e86a53a92cd1d9e1b0740f5d4cd2ae0bcab684bf0220208d555c7e24e4c01cf67dfa9161091533e9efd6d1602bb53a49f7195c16b03701255121036bd7943325ed9c9e1a44d98a8b5759c4bf4807df4312810ed5fc09dfb967811951ae"
        },
        "sequence": 4294967293
      }
    ],
    "vout": [
      {
        "value": 0.01040868,
        "n": 0,
        "scriptPubKey": {
          "asm": "OP_HASH160 29d13058087ddf2d48de404376fdcb5c4abff4bc OP_EQUAL",
          "desc": "addr(35W8E71bdDhQw4ZC7uUZvXG3qhyWVYxfMB)#4rtfrxzg",
          "hex": "a91429d13058087ddf2d48de404376fdcb5c4abff4bc87",
          "address": "35W8E71bdDhQw4ZC7uUZvXG3qhyWVYxfMB",
          "type": "scripthash"
        }
      }
    ],
    "hex": "0200000001c5167dd8f59fc3ed78fbea5ce574f21739de1d3197a704dc8a3f5e1ef0527304000000006f004730440220049d3138f841b63e96725cb9e86a53a92cd1d9e1b0740f5d4cd2ae0bcab684bf0220208d555c7e24e4c01cf67dfa9161091533e9efd6d1602bb53a49f7195c16b03701255121036bd7943325ed9c9e1a44d98a8b5759c4bf4807df4312810ed5fc09dfb967811951aefdffffff01e4e10f000000000017a91429d13058087ddf2d48de404376fdcb5c4abff4bc8700000000","blockhash":"000000000000000000036cb20420528cf0f00abb3a5716d80b5c87146b764d47",
    "confirmations":15235,
    "time":1690540748,
    "blocktime":1690540748
}
"#;

pub fn derive_privkey_from_merkle_root(merkle_root: Vec<u8>, initial_priv_key_hex: String) -> [u8; 32] {
    let rev_merkle_root: Vec<u8> = merkle_root.iter().rev().cloned().collect();
    let rev_merkle_root_hex = encode(rev_merkle_root);
    let path = get_path_from_commitment(rev_merkle_root_hex).unwrap();

    let initial_priv_key_bytes = decode(initial_priv_key_hex).expect("Invalid public key hex string");
    let mut priv_key_bytes = [0u8; 32];
    priv_key_bytes.copy_from_slice(&initial_priv_key_bytes);

    let initial_extended_privkey = ExtendedPrivateKey::new(priv_key_bytes).unwrap();
    let child_privkey = derive_child_priv_key(&initial_extended_privkey, &path.to_string());
    
    child_privkey
}

pub fn get_path_from_commitment(commitment: String) -> Option<String> {
    let path_size = 16;
    let child_size = 4;

    if commitment.len() != path_size * child_size {
        return None;
    }

    let mut derivation_path = String::new();
    for it in 0..path_size {
        let index = &commitment[it * child_size..it * child_size + child_size];
        let decoded_index = u64::from_str_radix(index, 16).unwrap();
        derivation_path.push_str(&decoded_index.to_string());
        if it < path_size - 1 {
            derivation_path.push('/');
        }
    }

    Some(derivation_path)
}

fn derive_child_priv_key(mut parent: &ExtendedPrivateKey<bip32::secp256k1::SecretKey>, path: &str) -> [u8; 32] {
    let mut extended_key = parent.clone();
    let mut private_key = parent.to_bytes();
    for step in path.split('/') {
        match step {
            "m" => continue,
            number => {
                if let Ok(index) = number.parse::<u32>() {
                    let new_extended_key = extended_key.derive_child(ChildNumber(index)).expect("Failed to derive child key");
                    private_key = new_extended_key.to_bytes();
                    extended_key = new_extended_key.clone();
                } else {
                    panic!("Invalid derivation path step: {}", step);
                }
            }
        }
    }
    private_key
}



fn main() {
    let merkle_root = "8d0ad2782d8f6e3f63c6f9611841c239630b55061d558abcc6bac53349edac70";
    let merkle_root_bytes = decode(merkle_root).expect("Invalid merkle root hex string");
    let priv_key = "3eb5b159e36d4395b5e602350c6975c17ec8d534a3e8b574144e3b8ca2d1ed09".to_string();
    let secret_key = derive_privkey_from_merkle_root(merkle_root_bytes, priv_key);
    println!("Secret key: {:?}", secret_key);
    let json_value: Value = from_str(TX_DATA_RES).unwrap();
    let value = 10000;
    let redeem_script_str = "OP_PUSHNUM_1 OP_PUSHBYTES_33 0274300392f1d981d80be1a709eb600355dabfb6cd4f1f67101bc994a01fede7a4 OP_PUSHNUM_1 OP_CHECKMULTISIG";
    let redeem_script_hex = encode(redeem_script_str);
    println!("{:?}", redeem_script_hex);
    let redeem_script = RedeemScript::from_str(&redeem_script_hex).unwrap(); 
    let input_signer = InputSigner::new(redeem_script);
    println!("Input signer: {:?}", input_signer);
    // let sign = input_signer.sign_input(&secret_key, &json_value, value).unwrap();
    // println!("Sign: {:?}", sign);
}
