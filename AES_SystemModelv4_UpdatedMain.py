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
class BinPol: # BinPol author: github.com/pcaro90 / modified by: EBranigan
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


class KeyExpansion:  # author: EBranigan    
    
    def __init__(self, key_hex, sbox):
        # Validate key length: Ensure the key is 128 bits (32 hex characters)
        if len(key_hex) != 32:
            raise ValueError("AES key must be 128 bits (32 hex characters).")
        
        # Initialize the S-Box (used in SubWord transformation)
        self.sbox = sbox  
        print(f"Initialized S-Box: {self.sbox}")  # Debugging line to confirm S-Box loading
        
        # Convert hex key string into a list of bytes
        self.key = self.hex_to_bytes(key_hex)
        
        # Generate all round keys for AES encryption using the provided key
        self.round_keys = self.key_expansion(self.key)

    @staticmethod
    def hex_to_bytes(hex_string):
        # Convert a hex string (e.g., "5468617473206D79204B756E67204675") into a list of byte integers
        return [int(hex_string[i:i + 2], 16) for i in range(0, len(hex_string), 2)]

    def sub_word(self, word):
        # Apply the S-Box substitution to each byte in a 4-byte word
        return [self.sbox[b] for b in word]  

    def rot_word(self, word):
        # Rotate the word by moving the first byte to the end
        return word[1:] + word[:1]

    def key_expansion(self, key):
        # Constants for AES-128 encryption
        Nk = 4  # Number of 32-bit words in the key (AES-128 uses 4 words for 128 bits)
        Nb = 4  # Number of columns in the AES state (always 4)
        Nr = 10  # Number of encryption rounds for AES-128

        # Initialize the round key array with the initial key (4 words of 4 bytes each)
        W = [[key[4 * i + j] for j in range(4)] for i in range(Nk)]

        # Generate the remaining round keys
        for i in range(Nk, Nb * (Nr + 1)):
            temp = W[i - 1]  # Last word in the current round

            if i % Nk == 0:
                # Apply transformations every Nk words: RotWord, SubWord, and XOR with Rcon
                temp = self.sub_word(self.rot_word(temp))  # Apply SubWord and RotWord transformations
                temp[0] ^= rcon[(i // Nk) - 1]  # XOR first byte with round constant

            # Generate new word by XORing with the word Nk positions back
            W.append([a ^ b for a, b in zip(W[i - Nk], temp)])

        # Flatten the list of words into round keys by grouping every Nb words into a single list
        return [sum(W[i:i + Nb], []) for i in range(0, len(W), Nb)]
    
    @staticmethod
    def user_input_key():
        # Continuously prompt the user for a valid 128-bit AES key (32 hex characters) until input is valid
        while True:
            key_hex = input("Enter a 128-bit AES key (32 hex characters): ").strip()
            
            # Validate key length and content (only hex characters)
            if len(key_hex) == 32 and all(c in '0123456789abcdefABCDEF' for c in key_hex):
                return key_hex
            else:
                print("Invalid key length or characters. Please enter exactly 32 hex characters.")


class MixColumns:  # author: EBranigan
    @staticmethod
    def gf_multiply(a, b):
        """Multiply two bytes in GF(2^8) using the AES field polynomial (0x11B).
        
        The multiplication is carried out bit by bit in the Galois Field GF(2^8),
        applying modular reduction by the irreducible polynomial for AES (0x1B) 
        whenever an overflow occurs in the high bit.
        
        Args:
            a (int): First byte to multiply.
            b (int): Second byte to multiply.
            
        Returns:
            int: Result of the multiplication in GF(2^8).
        """
        p = 0  # Product result initialized to 0
        for _ in range(8):
            if b & 1:  # Check if the least significant bit of b is set
                p ^= a  # XOR a into the result if bit is set
            hi_bit_set = a & 0x80  # Check if the high bit of a is set
            a <<= 1  # Shift a left by 1
            if hi_bit_set:
                a ^= 0x1B  # Reduce by AES irreducible polynomial if high bit was set
            b >>= 1  # Shift b right by 1
        return p

    @staticmethod
    def mix_columns(state):
        """Apply the MixColumns transformation to each column in the state matrix.
        
        The state matrix columns are transformed by matrix multiplication with
        a fixed polynomial matrix in GF(2^8), enhancing diffusion.
        
        Args:
            state (list of lists): 4x4 matrix representing the AES state.
            
        Returns:
            list of lists: New state matrix after the MixColumns transformation.
        """
        fixed_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]

        new_state = []
        for col in range(4):  # Process each column in the state
            new_column = []
            for row in range(4):
                val = 0
                for i in range(4):  # Multiply each element in the column by fixed matrix
                    val ^= MixColumns.gf_multiply(fixed_matrix[row][i], state[i][col]) % 256
                new_column.append(val % 256)  # Keep result within byte range
            new_state.append(new_column)
        
        # Transpose new_state back to match input format (column-wise to row-wise)
        return [[new_state[row][col] for row in range(4)] for col in range(4)]

    @staticmethod
    def inv_mix_columns(state):
        """Apply the Inverse MixColumns transformation for AES decryption.
        
        This method uses a different fixed matrix to reverse the MixColumns 
        transformation, ensuring the original state can be restored.
        
        Args:
            state (list of lists): 4x4 matrix representing the AES state.
            
        Returns:
            list of lists: New state matrix after the inverse MixColumns transformation.
        """
        inv_matrix = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x09, 0x0e]
        ]
        
        new_state = []
        for col in range(4):  # Process each column in the state
            new_column = []
            for row in range(4):
                val = 0
                for i in range(4):  # Multiply each element by the inverse matrix
                    val ^= MixColumns.gf_multiply(inv_matrix[row][i], state[i][col])
                new_column.append(val % 256)
            new_state.append(new_column)
        
        # Transpose new_state back to match input format
        return [[new_state[row][col] for row in range(4)] for col in range(4)]


class SubBytes:  # author: V_Mendy
    @staticmethod
    def execute(state, sbox):
        """Apply the SubBytes transformation by replacing each byte with an S-Box entry.
        
        Each byte in the state matrix is replaced with a corresponding value from the
        AES S-Box, implementing a nonlinear substitution.
        
        Args:
            state (list of lists): 4x4 matrix representing the AES state.
            sbox (list): 256-element list used for byte substitution.
            
        Returns:
            list of lists: Updated state matrix after SubBytes transformation.
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = sbox[state[i][j]]
        return state

    @staticmethod
    def inv_sub_bytes(state, inv_sbox):
        """Apply the Inverse SubBytes transformation using the inverse S-Box.
        
        Each byte in the state matrix is replaced with a corresponding value from the
        AES inverse S-Box, reversing the nonlinear substitution.
        
        Args:
            state (list of lists): 4x4 matrix representing the AES state.
            inv_sbox (list): 256-element list used for inverse byte substitution.
            
        Returns:
            list of lists: Updated state matrix after inverse SubBytes transformation.
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = inv_sbox[state[i][j]]
        return state


class ShiftRows:  # author: E Saji  
    @staticmethod
    def shift_rows(state):
        """Apply the ShiftRows transformation by cyclically shifting rows to the left.
        
        Rows 1 to 3 in the state matrix are shifted to the left by 1, 2, and 3 positions
        respectively. This transformation contributes to the diffusion process.
        
        Args:
            state (list of lists): 4x4 matrix representing the AES state.
            
        Returns:
            list of lists: Updated state matrix after ShiftRows transformation.
        """
        for r in range(1, 4):  # Only shift rows 1 to 3; row 0 remains unchanged
            state[r] = state[r][r:] + state[r][:r]
        return state

    @staticmethod
    def inv_shift_rows(state):
        """Apply the Inverse ShiftRows transformation by cyclically shifting rows to the right.
        
        Rows 1 to 3 in the state matrix are shifted to the right by 1, 2, and 3 positions
        respectively, reversing the ShiftRows transformation.
        
        Args:
            state (list of lists): 4x4 matrix representing the AES state.
            
        Returns:
            list of lists: Updated state matrix after inverse ShiftRows transformation.
        """
        for r in range(1, 4):  # Only shift rows 1 to 3; row 0 remains unchanged
            state[r] = state[r][-r:] + state[r][:-r]
        return state

class AddRoundKey:  # author: V_Mendy
    @staticmethod
    def execute(state, round_key):
        """Apply the AddRoundKey transformation, which XORs the state with the round key.
        
        The round key is derived from the original AES key using the key expansion. In each round,
        the round key is added to the state matrix by performing an XOR operation between corresponding 
        elements of the state matrix and the round key matrix.
        
        Args:
            state (list of lists): The current 4x4 state matrix, representing the AES data.
            round_key (list): A 16-byte list representing the round key, which will be transformed 
                              into a 4x4 matrix for the XOR operation.
            
        Returns:
            list of lists: The updated state matrix after the XOR with the round key.
        """
        
        # Transform the 16-byte round key into a 4x4 matrix format
        round_key_matrix = [
            [round_key[0], round_key[4], round_key[8], round_key[12]],   # First row of the round key matrix
            [round_key[1], round_key[5], round_key[9], round_key[13]],   # Second row
            [round_key[2], round_key[6], round_key[10], round_key[14]],  # Third row
            [round_key[3], round_key[7], round_key[11], round_key[15]]   # Fourth row
        ]
        
        # Output the round key matrix in a readable 4x4 hexadecimal format for debugging
        print("Round Key being added (4x4 hex):")
        for row in round_key_matrix:
            print(' '.join(f'{byte:02x}' for byte in row))  # Format each byte as a 2-digit hexadecimal value
        
        # Perform the XOR operation between the state matrix and the round key matrix.
        # This modifies the state matrix in place.
        for i in range(4):  # Iterate over each row
            for j in range(4):  # Iterate over each column
                state[i][j] ^= round_key_matrix[i][j]  # XOR corresponding elements of the state and round key matrices
        
        # Return the updated state after the AddRoundKey transformation
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
        """Initialize the AES encryption and decryption process.
        
        Args:
            key_hex (str): A string representing the 128-bit key in hexadecimal format (32 hex characters).
        """
        print("Initializing AES class...")

        # Load the standard AES S-box used for SubBytes operation
        self.sbox = self.load_sbox()  
        print("S-Box loaded:", self.sbox)
        
        # Calculate the inverse of the S-box (used in decryption)
        self.inv_sbox = invert_sbox(self.sbox)  
        print("Inverse S-Box calculated:", self.inv_sbox)
        
        # Initialize the KeyExpansion class to generate the round keys
        self.key_expansion = KeyExpansion(key_hex, self.sbox)
        self.round_keys = self.key_expansion.round_keys
        print("Key Expansion complete. Round keys (hex):")
        for i, key in enumerate(self.round_keys):
            hex_key = ' '.join([f'{byte:02x}' for byte in key])  # Print round keys in hex
            print(f"Round {i}: {hex_key}")
        
        # Initialize the MixColumns class (used in encryption and decryption)
        self.mix_columns = MixColumns()  
        self.inv_mix_columns = MixColumns()  # Inverse MixColumns uses the same class
        print("MixColumns classes initialized.")
    
    def load_sbox(self):
        """Load the AES S-box from the AES_base module.
        
        This function imports the S-box used for the SubBytes transformation, which is essential
        for both encryption and decryption. If loading fails, it will return None.
        
        Returns:
            list: The S-box used for the SubBytes operation, or None if the import fails.
        """
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from AES_base import sbox  # Import the sbox from AES_base.py
            return sbox
        except ImportError as e:
            print(f"Error loading S-box: {e}")
            return None

    def encrypt(self, plaintext_hex):
        """Encrypt the plaintext using AES encryption.
        
        Args:
            plaintext_hex (str): A string representing the plaintext to be encrypted in hexadecimal format.
        
        Returns:
            str: The encrypted ciphertext in hexadecimal format.
        """
        print("Starting encryption...")
        # Convert the plaintext hex string to a state matrix
        state = self.hex_to_state(plaintext_hex)
        print("State after hex to state conversion (hex):")
        print(self.state_to_hex(state))
    
        # Perform the initial AddRoundKey operation (round 0)
        state = AddRoundKey.execute(state, self.round_keys[0])
        print("State after initial AddRoundKey (hex):")
        print(self.state_to_hex(state))
    
        # Perform the main 9 rounds of AES encryption (Rounds 1-9)
        for round in range(1, 10):
            print(f"Round {round}...")
            state = SubBytes.execute(state, self.sbox)  # Apply SubBytes transformation
            print(f"State after SubBytes in round {round} (hex):")
            print(self.state_to_hex(state))
            
            state = ShiftRows.shift_rows(state)  # Apply ShiftRows transformation
            print(f"State after ShiftRows in round {round} (hex):")
            print(self.state_to_hex(state))
        
            state = MixColumns.mix_columns(state)  # Apply MixColumns transformation
            print(f"State after MixColumns in round {round} (hex):")
            print(self.state_to_hex(state))

            state = AddRoundKey.execute(state, self.round_keys[round])  # Apply AddRoundKey transformation
            print(f"State after AddRoundKey in round {round} (hex):")
            print(self.state_to_hex(state))
    
        # Final round (no MixColumns)
        print("Final round (round 10)...")
        state = SubBytes.execute(state, self.sbox)  # Apply SubBytes in final round
        print("State after SubBytes in final round (hex):")
        print(self.state_to_hex(state))
    
        state = ShiftRows.shift_rows(state)  # Apply ShiftRows in final round
        print("State after ShiftRows in final round (hex):")
        print(self.state_to_hex(state))
    
        state = AddRoundKey.execute(state, self.round_keys[10])  # Apply final AddRoundKey
        print("State after final AddRoundKey (hex):")
        print(self.state_to_hex(state))
    
        # Convert the final state matrix back to hex string (ciphertext)
        encrypted_hex = self.state_to_hex(state)
        print("Encrypted hex:", encrypted_hex)
    
        return encrypted_hex

    
    def decrypt(self, ciphertext_hex):
        """Decrypt the ciphertext using AES decryption.
        
        Args:
            ciphertext_hex (str): A string representing the ciphertext to be decrypted in hexadecimal format.
        
        Returns:
            str: The decrypted plaintext in hexadecimal format.
        """
        print(ciphertext_hex)
        new_cipher_text = AES.matrix_to_hex_string_by_column(ciphertext_hex)  # Adjust format
        print(new_cipher_text)

        print("Starting decryption...")
        # Convert the ciphertext hex string to a state matrix
        state = self.hex_to_state(new_cipher_text)
        print("State after hex to state conversion (hex):")
        print(self.state_to_hex(state))
    
        # Perform the initial AddRoundKey operation (round 10)
        state = AddRoundKey.execute(state, self.round_keys[10])
        print("State after initial AddRoundKey (hex):")
        print(self.state_to_hex(state))
    
        # Perform the main 9 rounds of AES decryption (Rounds 9-1)
        for round in range(9, 0, -1):
            print(f"Round {round} (decryption)...")
            state = ShiftRows.inv_shift_rows(state)  # Apply inverse ShiftRows
            print(f"State after inv_ShiftRows in round {round} (hex):")
            print(self.state_to_hex(state))

            state = SubBytes.inv_sub_bytes(state, self.inv_sbox)  # Apply inverse SubBytes
            print(f"State after inv_SubBytes in round {round} (hex):")
            print(self.state_to_hex(state))

            state = AddRoundKey.execute(state, self.round_keys[round])  # Apply AddRoundKey
            print(f"State after AddRoundKey in round {round} (hex):")
            print(self.state_to_hex(state))
        
            state = self.inv_mix_columns.inv_mix_columns(state)  # Apply inverse MixColumns
            print(f"State after inv_MixColumns in round {round} (hex):")
            print(self.state_to_hex(state))
    
        # Final round (no inv_MixColumns)
        print("Final round (round 0, decryption)...")
        state = ShiftRows.inv_shift_rows(state)  # Apply inverse ShiftRows in final round
        print("State after inv_ShiftRows in final round (hex):")
        print(self.state_to_hex(state))

        state = SubBytes.inv_sub_bytes(state, self.inv_sbox)  # Apply inverse SubBytes in final round
        print("State after inv_SubBytes in final round (hex):")
        print(self.state_to_hex(state))
    
        state = AddRoundKey.execute(state, self.round_keys[0])  # Apply final AddRoundKey
        print("State after final AddRoundKey (hex):")
        print(self.state_to_hex(state))
    
        decrypted_hex_matrix = self.state_to_hex(state)  # Convert decrypted state to hex
        print("Decrypted hex in matrix form:", decrypted_hex_matrix)
    
        # Convert state matrix back to hex string
        decrypted_hex = AES.matrix_to_hex_string_by_column(decrypted_hex_matrix)
        print("Decrypted message:", decrypted_hex)

        return decrypted_hex


    @staticmethod
    def hex_to_state(hex_string):
        """Convert a hexadecimal string to a 4x4 state matrix (list of lists)."""
        return [[int(hex_string[i*2+j*8:i*2+j*8+2], 16) for j in range(4)] for i in range(4)]

    def state_to_hex(self, state):
        """Convert a 4x4 state matrix back to a hexadecimal string."""
        hex_state = ""
        for i in range(4):
            hex_state += " ".join([f"{state[i][j]:02x}" for j in range(4)]) + "\n"
        return hex_state

    @staticmethod
    def matrix_to_hex_string_by_column(matrix_str):
        """Convert a matrix string (4x4 hex) back to a single hex string by reading column by column."""
        lines = [line.strip() for line in matrix_str.split('\n') if line.strip()]  # Clean up empty lines
        matrix = [line.split() for line in lines]  # Split lines into columns
        result = ''
        for col in range(4):  # Process columns
            for row in range(4):  # Process rows
                result += matrix[row][col]
        return result

    

""" # ------------------------------------------------------------------------------------------------
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
# ------------------------------------------------------------------------------------------------ """


def main():  # author: EBranigan    
    """Interactive function to encrypt or decrypt using AES."""
    # Step 1: Generate AES tables and load the S-Box
    print("Starting AES table generation...")
    generate()  # This function generates the AES S-box and other related tables
    print("AES table generation complete. Check 'AES_base.log' and 'AES_base.py' for details.")
    
    # Step 2: Load the S-box and compute the inverse S-box
    try:
        from AES_base import sbox  # Try to import the S-box from the generated file
        inv_sbox = invert_sbox(sbox)  # Calculate the inverse of the S-box
        print("Inverse S-Box generated successfully.")  # Inform the user about the inverse S-box generation
    except ImportError as e:
        # If the import fails, the AES_base.py file may not have been generated or is missing
        print("Error loading S-box. Ensure 'AES_base.py' is correctly generated.")
        return  # Exit the program if the S-box could not be loaded

    # Step 3: Get the AES key from the user input
    key_hex = get_valid_hex_key()  # Prompt the user for a valid AES key in hexadecimal format
    if not key_hex:
        print("Exiting due to invalid key.")  # If the key is invalid, exit the program
        return

    # Step 4: Initialize the AES class with the provided key
    aes = AES(key_hex)  # Create an AES instance using the provided 128-bit key

    # Step 5: Prompt the user for the operation mode (encrypt, decrypt, or both)
    mode = get_operation_mode()  # Prompt the user to select the operation mode
    if mode == 'e':  # If the user selected encryption
        plaintext_hex = get_valid_hex_input("plaintext", 32)  # Get valid plaintext in hexadecimal format
        if plaintext_hex:
            print("Encrypting plaintext...")  # Inform the user that encryption is starting
            ciphertext = aes.encrypt(plaintext_hex)  # Perform encryption
            print(f"Ciphertext (hex): {ciphertext}")  # Display the resulting ciphertext in hexadecimal format

    elif mode == 'd':  # If the user selected decryption
        ciphertext_hex = get_valid_hex_input("ciphertext", 32)  # Get valid ciphertext in hexadecimal format
        if ciphertext_hex:
            print("Decrypting ciphertext...")  # Inform the user that decryption is starting
            decrypted_plaintext = aes.decrypt(ciphertext_hex)  # Perform decryption
            print(f"Decrypted Plaintext (hex): {decrypted_plaintext}")  # Display the decrypted plaintext in hex format

    elif mode == 'b':  # If the user selected both encryption and decryption
        plaintext_hex = get_valid_hex_input("plaintext", 32)  # Get valid plaintext input
        if plaintext_hex:
            print("Encrypting plaintext...")  # Inform the user that encryption is starting
            ciphertext = aes.encrypt(plaintext_hex)  # Perform encryption
            print(f"Ciphertext (hex): {ciphertext}")  # Display the encrypted ciphertext

            print("Decrypting the generated ciphertext...")  # Inform the user that decryption is starting
            decrypted_plaintext = aes.decrypt(ciphertext)  # Perform decryption on the ciphertext
            print(f"Decrypted Plaintext (hex): {decrypted_plaintext}")  # Display the decrypted plaintext in hex format

            # Step 6: Validate that the decrypted plaintext matches the original input
            if decrypted_plaintext.lower() == plaintext_hex.lower():
                print("Success: Decrypted plaintext matches the original plaintext.")  # Inform the user if the decryption was successful
            else:
                print("Warning: Decrypted plaintext does not match the original plaintext.")  # If there is a mismatch, warn the user

def get_valid_hex_key():
    """Prompt user to input a valid 128-bit AES key in hex format (32 characters)."""
    while True:
        key_hex = input("Enter a 128-bit AES key (32 hex characters): ").strip()  # Prompt for the AES key
        if len(key_hex) == 32 and is_valid_hex(key_hex):  # Check if the key is exactly 32 hex characters
            return key_hex  # Return the valid key
        print("Invalid key. Please ensure it is 32 hex characters (128-bit).")  # Inform the user if the key is invalid

def get_operation_mode():
    """Prompt the user to select an operation mode: encrypt, decrypt, or both."""
    while True:
        mode = input("Choose mode: (e)ncrypt, (d)ecrypt, or (b)oth: ").strip().lower()  # Prompt for the operation mode
        if mode in ['e', 'd', 'b']:  # Check if the input is valid
            return mode  # Return the selected mode
        print("Invalid input. Please enter 'e' for encrypt, 'd' for decrypt, or 'b' for both.")  # Inform the user if the input is invalid

def get_valid_hex_input(label, expected_length):
    """Prompt the user to input a valid hex string of specified length."""
    while True:
        hex_input = input(f"Enter the {label} in hex ({expected_length // 2} bytes, {expected_length} hex characters): ").strip()  # Prompt for the hex input
        if len(hex_input) == expected_length and is_valid_hex(hex_input):  # Validate the input length and format
            return hex_input  # Return the valid input
        print(f"Invalid {label}. Please ensure it is {expected_length} hex characters.")  # Inform the user if the input is invalid

def is_valid_hex(hex_str):
    """Check if a string is a valid hex string."""
    try:
        int(hex_str, 16)  # Try to convert the string to an integer using base 16
        return True  # If conversion is successful, the string is valid hexadecimal
    except ValueError:
        return False  # If a ValueError is raised, the string is not valid hexadecimal



# Run main function
if __name__ == "__main__":
    main()
