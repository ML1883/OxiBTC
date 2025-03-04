use bitcoin::{
    Transaction, Network, 
    address::Address,
    secp256k1::{Secp256k1, SecretKey, PublicKey, Message},
    consensus::encode::serialize,
    blockdata::transaction::{TxIn, TxOut, OutPoint, Version},
    Amount, Sequence, ScriptBuf,
    absolute::LockTime,
    sighash::SighashCache,
    script::Builder
};
use std::str::FromStr;
use hex;

pub fn generate_transaction(
    private_key_hex: &str, 
    recipient_address: &str, 
    amount: u64, 
    fee: u64,
    prev_txid: &str,
    prev_vout: u32,
    total_input: u64,
    change_address: &str
) -> Result<String, String> {

    println!("Starting transaction generation...");
    println!("Input parameters:");
    println!("  Recipient address: {}", recipient_address);
    println!("  Amount to send: {} satoshis", amount);
    println!("  Fee: {} satoshis", fee);
    println!("  Previous txid: {}", prev_txid);
    println!("  Previous vout: {}", prev_vout);
    println!("  Total input: {} satoshis", total_input);
    println!("  Change address: {}", change_address);
    
    // Initialize secp256k1 context
    let secp = Secp256k1::new();
    println!("Secp256k1 context initialized");
    
    // Convert private key and derive public key
    println!("Converting private key: {}", private_key_hex);
    let private_key = match SecretKey::from_str(private_key_hex) {
        Ok(key) => {
            println!("Private key converted successfully");
            key
        },
        Err(e) => {
            println!("Error converting private key: {}", e);
            return Err(e.to_string());
        }
    };
    
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    println!("Public key derived: {}", public_key);
    
    // Create input - parse txid from hex string
    println!("Parsing txid from hex: {}", prev_txid);
    let txid = match bitcoin::Txid::from_str(prev_txid) {
        Ok(id) => {
            println!("Txid parsed successfully: {}", id);
            id
        },
        Err(e) => {
            println!("Error parsing txid: {}", e);
            return Err(e.to_string());
        }
    };
    
    let txin = TxIn {
        previous_output: OutPoint::new(txid, prev_vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0xFFFFFFFF),
        witness: bitcoin::Witness::new(),
    };
    println!("Input created: previous_output={:?}, sequence={}", txin.previous_output, txin.sequence);
    
    // Calculate the change to be returned to the sender
    println!("Checking if funds are sufficient...");
    println!("Total input: {}, Amount: {}, Fee: {}", total_input, amount, fee);
    if total_input < amount + fee {
        println!("ERROR: Insufficient funds: {} < {} + {}", total_input, amount, fee);
        return Err("Insufficient funds: input amount is less than output + fee".to_string());
    }
    
    let change = total_input - amount - fee;
    println!("Change calculated: {} satoshis", change);
    
    // Parse addresses with explicit network
    println!("Parsing recipient address: {}", recipient_address);
    let recipient = match Address::from_str(recipient_address) {
        Ok(addr) => {
            // println!("Recipient address parsed successfully: {}", addr);
            match addr.require_network(Network::Bitcoin) {
                Ok(a) => {
                    println!("Network validation successful");
                    a
                },
                Err(e) => {
                    println!("Network mismatch error: {}", e);
                    return Err(format!("Network mismatch: {}", e));
                }
            }
        },
        Err(e) => {
            println!("Error parsing recipient address: {}", e);
            return Err(format!("Invalid recipient address: {}", e));
        }
    };
    
    println!("Parsing change address: {}", change_address);
    let change_addr = match Address::from_str(change_address) {
        Ok(addr) => {
            // println!("Change address parsed successfully: {}", addr);
            match addr.require_network(Network::Bitcoin) {
                Ok(a) => {
                    println!("Network validation successful");
                    a
                },
                Err(e) => {
                    println!("Network mismatch error: {}", e);
                    return Err(format!("Network mismatch: {}", e));
                }
            }
        },
        Err(e) => {
            println!("Error parsing change address: {}", e);
            return Err(format!("Invalid change address: {}", e));
        }
    };
    
    // Create the transaction outputs with proper Amount objects
    let recipient_txout = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: recipient.script_pubkey(),
    };
    println!("Recipient output created: amount={}, script_pubkey={}", recipient_txout.value, recipient_txout.script_pubkey);
    
    let change_txout = TxOut {
        value: Amount::from_sat(change),
        script_pubkey: change_addr.script_pubkey(),
    };
    println!("Change output created: amount={}, script_pubkey={}", change_txout.value, change_txout.script_pubkey);
    
    // Create the transaction with proper types
    let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::from_consensus(0),
        input: vec![txin.clone()],
        output: vec![recipient_txout.clone(), change_txout.clone()],
    };
    
    println!("Transaction created: version={}, lock_time={}, input_count={}, output_count={}", 
             tx.version, tx.lock_time, tx.input.len(), tx.output.len());
    

    let sign_return = sign_legacy_transaction(&mut tx, &private_key);

    match sign_return {
        Ok(_) => {
            // Successfully signed the transaction
            println!("Transaction signed successfully.");
            // Proceed with further steps if needed
        },
        Err(e) => {
            // Handle the error (e.g., print the error message or log it)
            eprintln!("Error signing transaction: {}", e);
            // Handle the error case as appropriate (e.g., return, exit, or retry)
        },
    }     

    // Serialize and return the transaction in hex format
    let serialized_tx = serialize(&tx);
    println!("Transaction serialized: {} bytes", serialized_tx.len());
    let hex_result = hex::encode(serialized_tx);
    println!("Transaction hex: {}", hex_result);
    
    Ok(hex_result)
}


pub fn sign_legacy_transaction(tx: &mut Transaction, private_key: &SecretKey) -> Result<(), String> {
    let secp = Secp256k1::new();
    let cache = SighashCache::new(tx.clone());
    
    for (i, txin) in tx.input.iter_mut().enumerate() {
        // Get the sighash for legacy transactions
        let sighash = match cache.legacy_signature_hash(i, &txin.script_sig, bitcoin::EcdsaSighashType::All.to_u32()) {
            Ok(hash) => {
                let sighash_bytes: &[u8] = hash.as_ref();
                sighash_bytes.try_into().map_err(|_| "Sighash must be exactly 32 bytes".to_string())?
            },
            Err(e) => return Err(format!("Sighash error: {}", e)),
        };
        // Create message from the sighash
        let sighash_fixed: [u8; 32] = sighash;
        let msg = Message::from_digest_slice(&sighash_fixed).map_err(|e| format!("Invalid message: {}", e))?;
        
        // Sign the message
        let sig = secp.sign_ecdsa(&msg, private_key);
        
        // Add the hashtype to the signature
        let mut sig_with_hashtype = sig.serialize_der().to_vec();
        sig_with_hashtype.push(bitcoin::EcdsaSighashType::All.to_u32() as u8);
        
        // Get the public key
        let pubkey = PublicKey::from_secret_key(&secp, private_key);
        
        // Create script_sig: <signature> <pubkey>
        // In Bitcoin 0.32.5, we need to wrap byte slices with PushBytesBuf
        let sig_bytes = bitcoin::script::PushBytesBuf::try_from(sig_with_hashtype)
            .map_err(|_| "Signature too large".to_string())?;
            
        // For public key, we need to use the proper serialization format
        // PublicKey.serialize() returns [u8; 33] for compressed keys
        let mut pubkey_bytes = bitcoin::script::PushBytesBuf::new();
        bitcoin::script::PushBytesBuf::extend_from_slice(&mut pubkey_bytes,&pubkey.serialize())
            .map_err(|_| "Public key too large".to_string())?;
        
        // Now create the script
        let script_sig = Builder::new()
            .push_slice(sig_bytes)
            .push_slice(pubkey_bytes)
            .into_script();
        
        txin.script_sig = script_sig;
    }
    
    Ok(())
}