/*A file in which I want to develop a function that goes through the motions of generating a transaction itself instead of leaning on the 
Rust bitcoin library.

The current file is WIP and only seems to work with legacy adresses, don't rely on it.*/

use sha2::{Sha256, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use ripemd::Ripemd160;
use bs58;
use hex;

// Struct definitions for our transaction components
#[derive(Debug, Clone)]
struct OutPoint {
    txid: [u8; 32],
    vout: u32,
}

#[derive(Debug, Clone)]
struct TxInput {
    previous_output: OutPoint,
    script_sig: Vec<u8>,
    sequence: u32,
}

#[derive(Debug, Clone)]
struct TxOutput {
    value: u64,
    script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Transaction {
    version: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    lock_time: u32,
}

// #[derive(Debug)]
// enum AddressType {
//     P2PKH,
//     P2SH,
//     P2WPKH,
//     P2WSH,
// }

pub fn generate_raw_transaction(
    private_key_hex: &str,
    recipient_address: &str,
    amount: u64,
    fee: u64,
    prev_txid: &str,
    prev_vout: u32,
    total_input: u64,
    change_address: &str,
) -> Result<String, String> {
    println!("Starting raw transaction generation...");
    
    // 1. Initialize secp256k1 context
    let secp = Secp256k1::new();
    println!("Secp256k1 context initialized");
    
    // 2. Load private key and derive public key
    println!("Converting private key: {}", private_key_hex);
    let private_key_bytes = match hex::decode(private_key_hex) {
        Ok(bytes) => bytes,
        Err(e) => return Err(format!("Invalid private key hex: {}", e)),
    };
    
    if private_key_bytes.len() != 32 {
        return Err(format!("Private key must be 32 bytes, got {}", private_key_bytes.len()));
    }
    
    let mut private_key_array = [0u8; 32];
    private_key_array.copy_from_slice(&private_key_bytes);
    
    let private_key = match SecretKey::from_slice(&private_key_array) {
        Ok(key) => {
            println!("Private key loaded successfully");
            key
        },
        Err(e) => {
            println!("Error loading private key: {}", e);
            return Err(e.to_string());
        }
    };
    
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    println!("Public key derived: {}", public_key);
    
    // 3. Decode previous txid from hex
    println!("Parsing txid from hex: {}", prev_txid);
    let txid_bytes = match hex::decode(prev_txid) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(format!("TXID must be 32 bytes, got {}", bytes.len()));
            }
            let mut txid_array = [0u8; 32];
            // Reverse the bytes for little-endian encoding
            for i in 0..32 {
                txid_array[i] = bytes[31 - i];
            }
            txid_array
        },
        Err(e) => return Err(format!("Invalid txid hex: {}", e)),
    };
    
    // 4. Calculate change amount
    println!("Checking if funds are sufficient...");
    println!("Total input: {}, Amount: {}, Fee: {}", total_input, amount, fee);
    if total_input < amount + fee {
        println!("ERROR: Insufficient funds: {} < {} + {}", total_input, amount, fee);
        return Err("Insufficient funds: input amount is less than output + fee".to_string());
    }
    
    let change = total_input - amount - fee;
    println!("Change calculated: {} satoshis", change);
    
    // 5. Parse recipient and change addresses
    println!("Parsing recipient address: {}", recipient_address);
    let recipient_script = match address_to_script_pubkey(recipient_address) {
        Ok(script) => {
            println!("Recipient script created: {:?}", hex::encode(&script));
            script
        },
        Err(e) => return Err(format!("Invalid recipient address: {}", e)),
    };
    
    println!("Parsing change address: {}", change_address);
    let change_script = match address_to_script_pubkey(change_address) {
        Ok(script) => {
            println!("Change script created: {:?}", hex::encode(&script));
            script
        },
        Err(e) => return Err(format!("Invalid change address: {}", e)),
    };
    
    // 6. Create transaction structure
    let tx_input = TxInput {
        previous_output: OutPoint {
            txid: txid_bytes,
            vout: prev_vout,
        },
        script_sig: Vec::new(), // Empty script sig for now
        sequence: 0xFFFFFFFF,   // Default sequence
    };
    
    let recipient_output = TxOutput {
        value: amount,
        script_pubkey: recipient_script,
    };
    
    let change_output = TxOutput {
        value: change,
        script_pubkey: change_script,
    };
    
    let mut transaction = Transaction {
        version: 2,
        inputs: vec![tx_input],
        outputs: vec![recipient_output, change_output],
        lock_time: 0,
    };
    
    println!("Unsigned transaction created");
    
    // 7. Create the signature hash for the input
    let sighash = create_signature_hash(&transaction, 0, &get_p2pkh_script_code(&public_key))?;
    println!("Signature hash created: {}", hex::encode(&sighash));
    
    // 8. Sign the transaction
    let message = Message::from_digest_slice(&sighash).map_err(|e| e.to_string())?;
    let signature = secp.sign_ecdsa(&message, &private_key);
    
    println!("Transaction signed successfully");
    
    // 9. Create the script signature (scriptSig)
    let mut script_sig = Vec::new();
    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(0x01); // SIGHASH_ALL
    
    // DER signature length + signature + pubkey length + pubkey
    script_sig.push(sig_bytes.len() as u8);
    script_sig.extend_from_slice(&sig_bytes);
    script_sig.push(33); // Public key length (compressed)
    script_sig.extend_from_slice(&public_key.serialize());
    
    // 10. Update the transaction with the signature
    transaction.inputs[0].script_sig = script_sig;
    
    // 11. Serialize the complete transaction
    let serialized = serialize_transaction(&transaction);
    let hex_result = hex::encode(&serialized);
    
    println!("Transaction serialized: {} bytes", serialized.len());
    println!("Transaction hex: {}", hex_result);
    
    Ok(hex_result)
}

// Helper functions

// Serialize transaction to bytes
fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    let mut buffer = Vec::new();
    
    // Version
    buffer.extend_from_slice(&tx.version.to_le_bytes());
    
    // Input count (varint)
    buffer.extend_from_slice(&encode_varint(tx.inputs.len() as u64));
    
    // Inputs
    for input in &tx.inputs {
        // Previous output (txid + vout)
        buffer.extend_from_slice(&input.previous_output.txid);
        buffer.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        
        // Script sig length (varint)
        buffer.extend_from_slice(&encode_varint(input.script_sig.len() as u64));
        
        // Script sig
        buffer.extend_from_slice(&input.script_sig);
        
        // Sequence
        buffer.extend_from_slice(&input.sequence.to_le_bytes());
    }
    
    // Output count (varint)
    buffer.extend_from_slice(&encode_varint(tx.outputs.len() as u64));
    
    // Outputs
    for output in &tx.outputs {
        // Value
        buffer.extend_from_slice(&output.value.to_le_bytes());
        
        // Script pubkey length (varint)
        buffer.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
        
        // Script pubkey
        buffer.extend_from_slice(&output.script_pubkey);
    }
    
    // Locktime
    buffer.extend_from_slice(&tx.lock_time.to_le_bytes());
    
    buffer
}

// Convert a Bitcoin address to script_pubkey
fn address_to_script_pubkey(address: &str) -> Result<Vec<u8>, String> {
    // Decode base58 address
    let decoded = match bs58::decode(address).into_vec() {
        Ok(decoded) => decoded,
        Err(_) => {
            // Check if it's a bech32 address
            if address.starts_with("bc1") {
                return handle_bech32_address(address);
            }
            return Err("Invalid address format".to_string());
        }
    };
    
    if decoded.len() < 5 {
        return Err("Address too short".to_string());
    }
    
    // Check the version byte and create appropriate script
    let version_byte = decoded[0];
    let hash160 = &decoded[1..decoded.len() - 4]; // Remove version byte and checksum
    
    match version_byte {
        0x00 => {
            // P2PKH
            let mut script = Vec::new();
            script.push(0x76); // OP_DUP
            script.push(0xA9); // OP_HASH160
            script.push(hash160.len() as u8); // Push bytes
            script.extend_from_slice(hash160);
            script.push(0x88); // OP_EQUALVERIFY
            script.push(0xAC); // OP_CHECKSIG
            Ok(script)
        },
        0x05 => {
            // P2SH
            let mut script = Vec::new();
            script.push(0xA9); // OP_HASH160
            script.push(hash160.len() as u8); // Push bytes
            script.extend_from_slice(hash160);
            script.push(0x87); // OP_EQUAL
            Ok(script)
        },
        _ => Err(format!("Unsupported address version: {}", version_byte)),
    }
}

// Handle bech32 addresses (simplified)
fn handle_bech32_address(address: &str) -> Result<Vec<u8>, String> {
    // This is a simplified placeholder - a real implementation would parse
    // bech32 properly and handle both P2WPKH and P2WSH
    if address.starts_with("bc1q") {
        // Assume P2WPKH - would need a proper bech32 decoder
        let mut script = Vec::new();
        script.push(0x00); // OP_0
        script.push(0x14); // Push 20 bytes
        // Here we would add the actual witness program (hash160 of pubkey)
        // but we're simplifying for this blueprint
        for _ in 0..20 {
            script.push(0x00); // Placeholder
        }
        return Ok(script);
    }
    
    Err("Unsupported bech32 address".to_string())
}

// Create a signature hash (simplified version of BIP143 for legacy transactions)
fn create_signature_hash(tx: &Transaction, input_index: usize, script_code: &[u8]) -> Result<[u8; 32], String> {
    if input_index >= tx.inputs.len() {
        return Err("Input index out of range".to_string());
    }
    
    // Create a copy of the transaction for signing
    let mut tx_copy = tx.clone();
    
    // Clear all input scripts
    for input in &mut tx_copy.inputs {
        input.script_sig = Vec::new();
    }
    
    // Set the script of the input being signed
    tx_copy.inputs[input_index].script_sig = script_code.to_vec();
    
    // Serialize the modified transaction
    let mut preimage = serialize_transaction(&tx_copy);
    
    // Append SIGHASH_ALL
    preimage.extend_from_slice(&0x01u32.to_le_bytes());
    
    // Double SHA256
    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let result1 = hasher.finalize();
    
    let mut hasher = Sha256::new();
    hasher.update(result1);
    let result2 = hasher.finalize();
    
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result2);
    
    Ok(hash)
}

// Get P2PKH script code from public key
fn get_p2pkh_script_code(public_key: &PublicKey) -> Vec<u8> {
    // Calculate RIPEMD160(SHA256(public_key))
    let mut hasher = Sha256::new();
    hasher.update(public_key.serialize());
    let sha256_result = hasher.finalize();
    
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(sha256_result);
    let hash160 = ripemd_hasher.finalize();
    
    // Create P2PKH script: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = Vec::new();
    script.push(0x76); // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(20);   // Push 20 bytes
    script.extend_from_slice(&hash160);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xAC); // OP_CHECKSIG
    
    script
}

// Encode a number as a variable-length integer (varint)
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut buffer = vec![0xfd];
        buffer.extend_from_slice(&(value as u16).to_le_bytes());
        buffer
    } else if value <= 0xffffffff {
        let mut buffer = vec![0xfe];
        buffer.extend_from_slice(&(value as u32).to_le_bytes());
        buffer
    } else {
        let mut buffer = vec![0xff];
        buffer.extend_from_slice(&value.to_le_bytes());
        buffer
    }
}
