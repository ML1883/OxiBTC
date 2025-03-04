use hex;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use bs58;
use bech32::{self};
use bech32::{hrp, segwit};


pub fn generate_btc_address(private_key_hex: &str, address_type: &str) -> String {
    println!("Private Key (Hex): {}", private_key_hex);
    
    // Convert the hexadecimal private key string into a byte array (Vec<u8>)
    let private_key_bytes = match hex::decode(private_key_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error decoding hex: {}", e);
            return String::from("Invalid private key hex format");
        }
    };
    println!("Private Key (Bytes): {:x?}", private_key_bytes);
    
    // Initialize the secp256k1 context (used for elliptic curve operations)
    let secp = Secp256k1::new();
    
    // Create a secret key from the private key bytes
    let secret_key = match SecretKey::from_slice(&private_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error creating secret key: {}", e);
            return String::from("Invalid private key");
        }
    };
    
    // Derive the corresponding public key from the secret key
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    

    let _legacy = generate_legacy_address(&public_key); // Always call legacy
    match address_type {
        "segwit" => generate_segwit_address(&public_key),
        "legacy" => _legacy,
        _ => String::from("Invalid address type specified"),
    }
}

fn generate_legacy_address(public_key: &PublicKey) -> String {
    // Serialize the public key in compressed format (33 bytes)
    let public_key_bytes = public_key.serialize();
    println!("Public Key (Compressed): {:x?}", public_key_bytes);
    
    // Step 1: Compute SHA-256 hash of the public key
    let sha256_hash = Sha256::digest(&public_key_bytes);
    println!("SHA-256 of Public Key: {:x?}", sha256_hash);
    
    // Step 2: Compute RIPEMD-160 hash of the SHA-256 result
    let ripemd160_hash = Ripemd160::digest(&sha256_hash);
    println!("RIPEMD-160 of SHA-256: {:x?}", ripemd160_hash);
    
    // Step 3: Add version byte (0x00 for Bitcoin mainnet)
    let mut address_bytes = vec![0x00];
    address_bytes.extend_from_slice(&ripemd160_hash);
    println!("Address Bytes with Version: {:x?}", address_bytes);
    
    // Step 4: Compute checksum (first 4 bytes of double SHA-256)
    let checksum = Sha256::digest(&Sha256::digest(&address_bytes));
    let checksum = &checksum[..4]; // First 4 bytes as checksum
    println!("Checksum: {:x?}", checksum);
    
    // Step 5: Append checksum to the address bytes
    address_bytes.extend_from_slice(checksum);
    println!("Final Address Bytes (Before Base58Check): {:x?}", address_bytes);
    
    // Step 6: Encode in Base58Check to generate the final legacy address
    let btc_address = bs58::encode(address_bytes).into_string();
    // println!("Final Legacy Address: {}", btc_address);
    
    btc_address
}

fn generate_segwit_address(public_key: &PublicKey) -> String {
    // Serialize the public key in compressed format (33 bytes)
    let public_key_bytes = public_key.serialize();
    println!("Public Key (Compressed): {:x?}", public_key_bytes);
    
    // Step 1: Compute SHA-256 hash of the public key
    let sha256_hash = Sha256::digest(&public_key_bytes);
    println!("SHA-256 of Public Key: {:x?}", sha256_hash);
    
    // Step 2: Compute RIPEMD-160 hash of the SHA-256 result
    let ripemd160_hash = Ripemd160::digest(&sha256_hash);
    println!("RIPEMD-160 of SHA-256: {:x?}", ripemd160_hash);
    
    // Step 3: For SegWit P2WPKH, we use the Bech32 encoding with a witness program
    // The witness program consists of a version byte (0) followed by the 20-byte hash
    let witness_program = ripemd160_hash.to_vec();


    // Encode a taproot address suitable for use on mainnet.
    let segwitv1 = segwit::encode_v1(hrp::BC, &witness_program);
    // let segwitv0 = segwit::encode_v0(hrp::TB, &witness_program);

    
    // Convert the witness program to 5-bit values as required by Bech32
    // let data = witness_program.to_base32();


    // Step 4: Encode using Bech32 with the "bc" human-readable part (HRP) for mainnet
    // The witness version is encoded separately in the Bech32 format
    match segwitv1 {
        Ok(address) => {
            println!("Final SegWit v1 Address: {}", address);
            address
        },
        Err(e) => {
            eprintln!("Error encoding Bech32 address: {:?}", e);
            String::from("Error generating SegWit address")
        }
    }

}