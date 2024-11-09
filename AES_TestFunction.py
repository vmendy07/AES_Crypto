from AES_SystemModelv4_UpdatedMain import AES

# ------------------------------------------------------------------------------------------------
# Test function for AES encryption and decryption   
def test_aes_encryption():
    plaintext_hex = "54776F204F6E65204E696E652054776F"  # Example plaintext (in hex)
    
    # Initialize the AES object with a key
    key_hex = "5468617473206D79204B756E67204675"  # Example key (in hex)
    aes = AES(key_hex)
    
    # Encrypt the plaintext
    print("Original Plaintext (hex):", plaintext_hex)
    ciphertext = aes.encrypt(plaintext_hex)
    print(f"Ciphertext: {ciphertext}")
    
    # Decrypt the ciphertext
    decrypted_plaintext = aes.decrypt(ciphertext)
    print(f"Decrypted Plaintext (hex): {decrypted_plaintext}")
    
    # Check if the decrypted plaintext matches the original plaintext (case-insensitive)
    if decrypted_plaintext.lower() != plaintext_hex.lower():
        print("Decryption failed: Decrypted plaintext does not match the original.")
        print("Original Plaintext:", plaintext_hex)
        print("Decrypted Plaintext:", decrypted_plaintext)
    else:
        print("Test passed! Decryption matched the original plaintext.")


# Run the test
test_aes_encryption()
# ------------------------------------------------------------------------------------------------