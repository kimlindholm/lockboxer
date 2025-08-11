use lockboxer::Vault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = lockboxer::generate_key();
    let vault = Vault::new(&key);

    let plaintext = b"plaintext";
    println!("Plaintext: {}", std::str::from_utf8(plaintext)?);

    // Encrypt the plaintext
    let encrypted = vault.encrypt(plaintext)?;
    println!("Encrypted: {}", hex::encode_upper(&encrypted));

    // Decrypt the ciphertext
    let decrypted = vault.decrypt(&encrypted)?;
    println!("Decrypted: {}", decrypted);

    assert_eq!(&decrypted.as_bytes(), plaintext);

    Ok(())
}
