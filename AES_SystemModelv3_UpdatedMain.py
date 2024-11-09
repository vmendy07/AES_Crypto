# AES_SystemModelv2.py

# AES

import sys
import os
import AES_base

# Add the current directory to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

#if not os.path.exists('AES_base.py'):
#    print("AES_base.py file is missing!")
#else:
#    print("AES_base.py file found!")

#print("Current working directory:", os.getcwd())
#print(AES_base.sbox)

# Round constants for key expansion
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# ------------------------------------------------------------------------------------------------
# Binary Polynomial Representation and Operations in GF(2^8) for AES table generation   
class BinPol: # BinPol author: github.com/pcaro90
    """Binary polynomial representation and operations in GF(2^8) for AES table generation."""

    def __init__(self, x, irreducible_polynomial=None, grade=None):
        self.dec = x  # Decimal representation
        self.hex = hex(self.dec)[2:]  # Hex representation (without '0x' prefix)
        # Reversed binary representation list of bits
        self.bin = reversed(list(bin(self.dec)[2:]))
        self.bin = [int(bit) for bit in self.bin]

        # Determine polynomial grade if not provided
        self.grade = grade if grade is not None else len(self.bin) - 1
        self.irreducible_polynomial = irreducible_polynomial

    def __str__(self):
        h = self.hex
        if self.dec < 16:
            h = '0' + h  # Ensure hex format consistency
        return h

    def __repr__(self):
        return str(self)

    def __len__(self):
        return self.grade

    def __setitem__(self, key, value):
        # Ensure the bit at the specified position is either 0 or 1
        if value in [0, 1]:
            while len(self.bin) <= key:
                self.bin.append(0)  # Extend list if necessary
            self.bin[key] = value
        self.__update_from_bin()

    def __getitem__(self, key):
        return self.bin[key] if key < len(self.bin) else 0

    def __add__(self, x):
        # XOR addition (polynomial addition in GF(2))
        # print(f"Adding {self} + {x}")
        result = BinPol(self.dec, self.irreducible_polynomial)
        for i, bit in enumerate(x.bin):
            result[i] ^= bit
        result.__update_from_bin()
        return result

    def __mul__(self, x):
        # Polynomial multiplication in GF(2) with modular reduction
        #print(f"Multiplying {self} * {x}")
        result = BinPol(0, self.irreducible_polynomial)
        for i, a_bit in enumerate(self.bin):
            for j, b_bit in enumerate(x.bin):
                if a_bit and b_bit:
                    result[i + j] ^= 1
        result.__update_from_bin()
        return result

    def __pow__(self, x):
        # Exponentiation with modular reduction
        # print(f"Exponentiating {self} to the power of {x}")
        result = BinPol(1, self.irreducible_polynomial)
        for i in range(1, x + 1):
            result = result * BinPol(self.dec)
            if result.irreducible_polynomial and result.grade >= result.irreducible_polynomial.grade:
                result += result.irreducible_polynomial
            result.__update_from_bin()
        return result

    def __update_from_bin(self):
        # Update decimal and hex representations after modifying binary representation
        self.__remove_most_significant_zeros()
        self.dec = sum([bit << i for i, bit in enumerate(self.bin)])
        self.hex = hex(self.dec)[2:]
        self.grade = len(self.bin) - 1

    def __remove_most_significant_zeros(self):
        # Remove leading zeros from binary representation
        last = 0
        for i, bit in enumerate(self.bin):
            if bit:
                last = i
        del self.bin[last + 1:]


def inv_pol(pol, antilog, log):
    # Compute the multiplicative inverse of a polynomial in GF(2^8)
    if pol.dec == 0:
        # print(f"No inverse for {pol} (0 in GF(2^8))")
        return BinPol(0, pol.irreducible_polynomial)
    else:
        inverse = BinPol(antilog[0xFF - log[pol.dec].dec].dec, pol.irreducible_polynomial)
        # print(f"Inverse of {pol} is {inverse}")
        return inverse


def affine_transformation(b):
    # Perform the affine transformation required for AES S-box
    # print(f"Applying affine transformation to {b}")
    b1 = BinPol(b.dec, b.irreducible_polynomial)
    c = BinPol(0b01100011)
    for i in range(8):
        b1[i] = b[i] ^ b[(i + 4) % 8] ^ b[(i + 5) % 8] ^ b[(i + 6) % 8] ^ b[(i + 7) % 8] ^ c[i]
    return b1


def str_16x16(table):
    # Format table output in a 16x16 grid
    s = '\t' + '\t'.join(hex(i) for i in range(16)) + '\n'
    for i in range(16):
        s += hex(i) + '\t' + '\t'.join(str(table[i * 16 + j]) for j in range(16)) + '\n'
    return s


def generate():
    """Generate F256 field, log, antilog, S-box, and related AES tables."""
    try:
        # Open a file in write mode to log the generated AES tables.
        with open('AES_base.log', 'w') as f:
            
            # Define the irreducible polynomial for the field F256 (AES field)
            # This polynomial is used in all operations in the finite field F256.
            irreducible_polynomial = BinPol(0b100011011)  # 0x11b (in binary)

            # Define the primitive element for the field F256 (AES uses 3 as the generator for F256)
            primitive = BinPol(3, irreducible_polynomial)  # The generator element for the field

            # Generate the antilog table, which contains the powers of the primitive element.
            # The antilog table is used to perform exponentiation in the finite field.
            antilog = [primitive**i for i in range(256)]  # Compute powers of the primitive

            # Initialize the log table, which maps elements of F256 to their logarithms
            log = [BinPol(0, irreducible_polynomial) for _ in range(256)]  # Initialize with zeroes
            
            # Build the log table by using the antilog table. The log of an element is its position in the antilog table.
            for i, a in enumerate(antilog):
                log[a.dec] = BinPol(i, irreducible_polynomial)  # Map antilog values to their corresponding log positions
            
            # Generate the inverse table by calculating the inverse of each element in F256
            # Inversion is done by using the precomputed antilog and log tables.
            inv = [inv_pol(BinPol(i), antilog, log) for i in range(256)]  # Compute the inverse of each element
            
            # Generate the S-Box by applying an affine transformation to each of the inverses
            # This step is a part of the AES non-linear transformation
            sbox = [affine_transformation(a) for a in inv]  # Apply the affine transformation to each inverse

            # Write the results to the log file for reference
            f.write("Generated AES S-box and related tables.\n")
            f.write("Irreducible Polynomial: " + str(irreducible_polynomial) + "\n")  # Log the irreducible polynomial used
            f.write("S-Box:\n" + str_16x16(sbox) + "\n")  # Log the S-box in 16x16 format
            
            # Print the S-Box to the console in a readable format (16x16 grid)
            print("Generated S-Box:")
            print(str_16x16(sbox))  # Print S-box in 16x16 format to the console

    except Exception as e:
        # If any error occurs during the generation of the tables, print the error message and exit.
        print("Error during AES table generation:", e)
        sys.exit()

    # Save the generated AES tables into a Python module file for future use
    try:
        with open('AES_base.py', 'w') as f:
            # Write the generated S-box and other constants to a Python file.
            # This allows users to import and reuse the tables without needing to regenerate them.
            s = '''
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Generated AES tables for S-box and other constants

sbox = {0}

'''.format([i.dec for i in sbox])  # Convert the S-box elements to their decimal values and format them for Python

            # Save the string into the Python file
            f.write(s)
    except Exception as e:
        # If an error occurs while saving to the Python module, print the error message and exit.
        print("Error saving AES_base.py:", e)
        sys.exit()

def invert_sbox(sbox):
    inv_sbox = [0] * 256
    for i in range(256):
            inv_sbox[sbox[i]] = i
    return inv_sbox


class KeyExpansion:
    
    def __init__(self, key_hex, sbox):
        if len(key_hex) != 32:
            raise ValueError("AES key must be 128 bits (32 hex characters).")
        self.sbox = sbox  # Initialize the S-Box passed from AES
        print(f"Initialized S-Box: {self.sbox}")  # Debugging line
        self.key = self.hex_to_bytes(key_hex)
        self.round_keys = self.key_expansion(self.key)

    @staticmethod
    def hex_to_bytes(hex_string):
        return [int(hex_string[i:i + 2], 16) for i in range(0, len(hex_string), 2)]

    def sub_word(self, word):
        return [self.sbox[b] for b in word]  # Use the class's sbox

    def rot_word(self, word):
        return word[1:] + word[:1]

    def key_expansion(self, key):
        Nk = 4  # Number of 32-bit words in the key (AES-128 uses 4)
        Nb = 4  # Number of 32-bit words in a block
        Nr = 10  # Number of rounds for AES-128
        W = [[key[4 * i + j] for j in range(4)] for i in range(Nk)]

        for i in range(Nk, Nb * (Nr + 1)):
            temp = W[i - 1]
            if i % Nk == 0:
                temp = self.sub_word(self.rot_word(temp)) # SubWord and RotWord 
                temp[0] ^= rcon[(i // Nk) - 1] # XOR with round constant
            W.append([a ^ b for a, b in zip(W[i - Nk], temp)]) # XOR with previous word

        return [sum(W[i:i + Nb], []) for i in range(0, len(W), Nb)]
    
    @staticmethod
    def user_input_key():
        # Prompt the user for a valid 128-bit AES key (32 hex characters)
        while True:
            key_hex = input("Enter a 128-bit AES key (32 hex characters): ").strip()
            if len(key_hex) == 32 and all(c in '0123456789abcdefABCDEF' for c in key_hex):
                return key_hex
            else:
                print("Invalid key length or characters. Please enter exactly 32 hex characters.")

class MixColumns:
    @staticmethod
    def gf_multiply(a, b):
        """Multiply two bytes in GF(2^8) with the AES field polynomial."""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80  # Check if the high bit is set
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # Irreducible polynomial for AES
            b >>= 1
        return p

    @staticmethod
    def mix_columns(state):
        fixed_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]

        new_state = []
        for col in range(4):
            new_column = []
            for row in range(4):
                val = 0
                for i in range(4):
                    val ^= MixColumns.gf_multiply(fixed_matrix[row][i], state[i][col]) % 256
                new_column.append(val % 256)  # Constrain to byte range
            new_state.append(new_column)
        
        # Transpose new_state back to match input format
        return [[new_state[row][col] for row in range(4)] for col in range(4)]

    @staticmethod
    def inv_mix_columns(state):
        """Perform the Inverse MixColumns transformation on the entire state matrix."""
        inv_matrix = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x09, 0x0e]
        ]
        
        new_state = []
        for col in range(4):
            new_column = []
            for row in range(4):
                val = 0
                for i in range(4):
                    val ^= MixColumns.gf_multiply(inv_matrix[row][i], state[i][col])
                new_column.append(val % 256)
            new_state.append(new_column)
        
        # Transpose new_state back to match input format
        return [[new_state[row][col] for row in range(4)] for col in range(4)]

    
class SubBytes:
    @staticmethod
    def execute(state, sbox):
        for i in range(4):
            for j in range(4):
                state[i][j] = sbox[state[i][j]]
        return state

    @staticmethod
    def inv_sub_bytes(state, inv_sbox):
        for i in range(4):
            for j in range(4):
                state[i][j] = inv_sbox[state[i][j]]
        return state

class ShiftRows:
    @staticmethod
    def shift_rows(state):
        for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]
        return state

    @staticmethod
    def inv_shift_rows(state):
        for r in range(1, 4):
            state[r] = state[r][-r:] + state[r][:-r]
        return state

class AddRoundKey:
    @staticmethod
    def execute(state, round_key):
        # Correct the way the round_key is split into a 4x4 matrix
        round_key_matrix = [
            [round_key[0], round_key[4], round_key[8], round_key[12]],   # First row
            [round_key[1], round_key[5], round_key[9], round_key[13]],   # Second row
            [round_key[2], round_key[6], round_key[10], round_key[14]],  # Third row
            [round_key[3], round_key[7], round_key[11], round_key[15]]   # Fourth row
        ]
        
        # Print the round key in 4x4 hex format
        print("Round Key being added (4x4 hex):")
        for row in round_key_matrix:
            print(' '.join(f'{byte:02x}' for byte in row))
        
        # Perform XOR operation between the state matrix and the round key matrix
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key_matrix[i][j]  # XOR corresponding elements
        
        return state


#def pkcs7_pad(plaintext_hex):
#    """Apply PKCS7 padding to the plaintext (hex string)."""
#    # Determine the number of bytes to pad
#    pad_length = 16 - (len(plaintext_hex) // 2) % 16
#    padding = '{:02x}'.format(pad_length) * pad_length
#    return plaintext_hex + padding

#def pkcs7_unpad(padded_hex):
#    """Remove PKCS7 padding from the decrypted plaintext (hex string)."""
#    pad_length = int(padded_hex[-2:], 16)
#    return padded_hex[:-2*pad_length]


class AES:
    def __init__(self, key_hex):
        print("Initializing AES class...")
        self.sbox = self.load_sbox()  # Load S-Box
        print("S-Box loaded:", self.sbox)
        
        self.inv_sbox = invert_sbox(self.sbox)  # Calculate inverse S-box
        print("Inverse S-Box calculated:", self.inv_sbox)
        
        self.key_expansion = KeyExpansion(key_hex, self.sbox)
        self.round_keys = self.key_expansion.round_keys
        print("Key Expansion complete. Round keys (hex):")
        for i, key in enumerate(self.round_keys):
            hex_key = ' '.join([f'{byte:02x}' for byte in key])
            print(f"Round {i}: {hex_key}")
        
        self.mix_columns = MixColumns()  # Initialize the MixColumns class
        self.inv_mix_columns = MixColumns()  # Initialize the inverse MixColumns class (same class)
        print("MixColumns classes initialized.")
    
    def load_sbox(self):
        try:
            # Add the current directory to the system path so Python can find AES_base.py
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))

            # Try to import the sbox from AES_base
            from AES_base import sbox
            return sbox
        except ImportError as e:
            print(f"Error loading S-box: {e}")
            return None

    def encrypt(self, plaintext_hex):
        print("Starting encryption...")
        #padded_plaintext = pkcs7_pad(plaintext_hex)
        #print("Padded plaintext (hex):", padded_plaintext)
        
        state = self.hex_to_state(plaintext_hex)
        print("State after hex to state conversion (hex):")
        print(self.state_to_hex(state))
    
        state = AddRoundKey.execute(state, self.round_keys[0])
        print("State after initial AddRoundKey (hex):")
        print(self.state_to_hex(state))
    
        for round in range(1, 10):
            print(f"Round {round}...")
            state = SubBytes.execute(state, self.sbox)
            print(f"State after SubBytes in round {round} (hex):")
            print(self.state_to_hex(state))
            
            state = ShiftRows.shift_rows(state)
            print(f"State after ShiftRows in round {round} (hex):")
            print(self.state_to_hex(state))
        
            state = MixColumns.mix_columns(state)
            print(f"State after MixColumns in round {round} (hex):")
            print(self.state_to_hex(state))

            state = AddRoundKey.execute(state, self.round_keys[round])
            print(f"State after AddRoundKey in round {round} (hex):")
            print(self.state_to_hex(state))
    
        # Final round (no MixColumns)
        print("Final round (round 10)...")
        state = SubBytes.execute(state, self.sbox)
        print("State after SubBytes in final round (hex):")
        print(self.state_to_hex(state))
    
        state = ShiftRows.shift_rows(state)
        print("State after ShiftRows in final round (hex):")
        print(self.state_to_hex(state))
    
        state = AddRoundKey.execute(state, self.round_keys[10])
        print("State after final AddRoundKey (hex):")
        print(self.state_to_hex(state))
    
        encrypted_hex = self.state_to_hex(state)
        print("Encrypted hex:", encrypted_hex)
    
        return encrypted_hex

    
    def decrypt(self, ciphertext_hex):
        print(ciphertext_hex)
        new_cipher_text = AES.matrix_to_hex_string_by_column(ciphertext_hex)
        print(new_cipher_text)

        print("Starting decryption...")
        state = self.hex_to_state(new_cipher_text)
        print("State after hex to state conversion (hex):")
        print(self.state_to_hex(state))
    
        state = AddRoundKey.execute(state, self.round_keys[10])
        print("State after initial AddRoundKey (hex):")
        print(self.state_to_hex(state))
    
        for round in range(9, 0, -1):
            print(f"Round {round} (decryption)...")


            # Inv Shift Rows
            state = ShiftRows.inv_shift_rows(state)
            print(f"State after inv_ShiftRows in round {round} (hex):")
            print(self.state_to_hex(state))

            # Inv SubBytes            
            state = SubBytes.inv_sub_bytes(state, self.inv_sbox)
            print(f"State after inv_SubBytes in round {round} (hex):")
            print(self.state_to_hex(state))

            # Add Round Key
            state = AddRoundKey.execute(state, self.round_keys[round])
            print(f"State after AddRoundKey in round {round} (hex):")
            print(self.state_to_hex(state))
        
            # Inv Mix Columns        
            state = self.inv_mix_columns.inv_mix_columns(state)
            print(f"State after inv_MixColumns in round {round} (hex):")
            print(self.state_to_hex(state))


    
        # Final round (no inv_MixColumns)
        print("Final round (round 0, decryption)...")

        
        state = ShiftRows.inv_shift_rows(state)
        print("State after inv_ShiftRows in final round (hex):")
        print(self.state_to_hex(state))

        state = SubBytes.inv_sub_bytes(state, self.inv_sbox)
        print("State after inv_SubBytes in final round (hex):")
        print(self.state_to_hex(state))
    
        state = AddRoundKey.execute(state, self.round_keys[0])
        print("State after final AddRoundKey (hex):")
        print(self.state_to_hex(state))
    
        decrypted_hex_matrix = self.state_to_hex(state)
        print("Decrypted hex in matrix form:", decrypted_hex_matrix)
    
        # decrypted_plaintext = pkcs7_unpad(decrypted_hex)
        # print("Decrypted plaintext (hex after unpadding):", decrypted_plaintext)
        
        # Convert state matrix back to hex string
        decrypted_hex = AES.matrix_to_hex_string_by_column(decrypted_hex_matrix)
        print("Decrypted message:", decrypted_hex)

        return decrypted_hex


    @staticmethod
    def hex_to_state(hex_string):
        return [[int(hex_string[i*2+j*8:i*2+j*8+2], 16) for j in range(4)] for i in range(4)]

    def state_to_hex(self, state):
        hex_state = ""
        for i in range(4):
            hex_state += " ".join([f"{state[i][j]:02x}" for j in range(4)]) + "\n"
        return hex_state
    # @staticmethod
    def matrix_to_hex_string_by_column(matrix_str):
        # Split into lines and remove empty lines
        lines = [line.strip() for line in matrix_str.split('\n') if line.strip()]
        
        # Split each line into values
        matrix = [line.split() for line in lines]
        
        # Read column by column and join
        result = ''
        for col in range(4):  # For each column
            for row in range(4):  # For each row
                result += matrix[row][col]
                
        return result
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

# Main function to interactively encrypt or decrypt using AES   
def main():
    # Generate AES tables and prompt the user for action
    print("Starting AES table generation...")
    generate()  # Generate the S-box and related tables
    print("AES table generation complete. Check 'AES_base.log' and 'AES_base.py'.")

    # Import S-box directly from AES_base and calculate inverse S-box
    from AES_base import sbox
    inv_sbox = invert_sbox(sbox)
    print("Inverse S-Box generated.")  # Feedback to user

    # Prompt the user to enter a 128-bit AES key (32 hex characters)
    key_hex = KeyExpansion.user_input_key()  # Receive a hex key from the user
    print("\nUser-provided key in hex:", key_hex)

    # Initialize AES class with the user-provided key
    aes = AES(key_hex)
    
    # Ask the user if they want to encrypt, decrypt, or do both
    while True:
        mode = input("\nWould you like to (e)ncrypt, (d)ecrypt, or (b)oth? Enter 'e' for encryption, 'd' for decryption, or 'b' for both: ").strip().lower()
        if mode in ["e", "d", "b"]:
            break
        else:
            print("Invalid input. Please enter 'e' for encryption, 'd' for decryption, or 'b' for both.")

    # Encrypt mode
    if mode == "e":
        # Get plaintext input from the user
        plaintext_hex = input("Enter the plaintext in hex (16 bytes, 32 hex characters): ").strip()
        
        # Encrypt the plaintext
        print("Encrypting plaintext...")
        ciphertext = aes.encrypt(plaintext_hex)
        
        # Display the encrypted ciphertext
        print(f"Ciphertext (hex): {ciphertext}")

    # Decrypt mode
    elif mode == "d":
        # Get ciphertext input from the user
        ciphertext_hex = input("Enter the ciphertext in hex (16 bytes, 32 hex characters): ").strip()
        
        # Decrypt the ciphertext
        print("Decrypting ciphertext...")
        decrypted_plaintext = aes.decrypt(ciphertext_hex)
        
        # Display the decrypted plaintext
        print(f"Decrypted Plaintext (hex): {decrypted_plaintext}")

    # Both encrypt and decrypt mode
    elif mode == "b":
        # Get plaintext input from the user
        plaintext_hex = input("Enter the plaintext in hex (16 bytes, 32 hex characters): ").strip()
        
        # Encrypt the plaintext
        print("Encrypting plaintext...")
        ciphertext = aes.encrypt(plaintext_hex)
        print(f"Ciphertext (hex): {ciphertext}")
        
        # Decrypt the ciphertext
        print("Decrypting the generated ciphertext...")
        decrypted_plaintext = aes.decrypt(ciphertext)
        
        # Display the decrypted plaintext
        print(f"Decrypted Plaintext (hex): {decrypted_plaintext}")
        
        # Verify the decryption result (case-insensitive)
        if decrypted_plaintext.lower() == plaintext_hex.lower():
            print("Success: Decrypted plaintext matches the original plaintext.")
        else:
            print("Warning: Decrypted plaintext does not match the original plaintext.")

# Run main function
if __name__ == "__main__":
    main()

