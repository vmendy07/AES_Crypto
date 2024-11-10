# AES_SystemModel.py
"""
Advanced Encryption Standard (AES) Implementation
This module implements the AES encryption algorithm with visualization capabilities.
The implementation includes key expansion, encryption/decryption operations, and a REST API interface.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

app = Flask(__name__)
CORS(app)
import AES_base

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Round constants used in key expansion
# Each value represents a power of x in GF(2^8)
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

class BinPol:
    """
    Binary polynomial representation for finite field arithmetic in GF(2^8).
    Used for AES table generation and field operations.
    
    Attributes:
        dec (int): Decimal representation of the polynomial
        hex (str): Hexadecimal representation
        bin (list): Binary representation as list of coefficients
        grade (int): Degree of the polynomial
        irreducible_polynomial: The field's irreducible polynomial
    """

    def __init__(self, x, irreducible_polynomial=None, grade=None):
        self.dec = x
        self.hex = hex(self.dec)[2:]
        self.bin = [int(bit) for bit in reversed(list(bin(self.dec)[2:]))]
        self.grade = grade if grade is not None else len(self.bin) - 1
        self.irreducible_polynomial = irreducible_polynomial

    def __str__(self):
        """Returns zero-padded hexadecimal representation."""
        h = self.hex
        return '0' + h if self.dec < 16 else h

    def __repr__(self):
        """Returns string representation for debugging."""
        return str(self)

    def __len__(self):
        """Returns polynomial degree."""
        return self.grade

    def __setitem__(self, key, value):
        """Sets coefficient at specified position."""
        if value in [0, 1]:
            while len(self.bin) <= key:
                self.bin.append(0)
            self.bin[key] = value
        self.__update_from_bin()

    def __getitem__(self, key):
        """Gets coefficient at specified position."""
        return self.bin[key] if key < len(self.bin) else 0

    def __add__(self, x):
        """
        Implements polynomial addition in GF(2).
        Addition is performed bitwise using XOR operation.
        """
        result = BinPol(self.dec, self.irreducible_polynomial)
        for i, bit in enumerate(x.bin):
            result[i] ^= bit
        result.__update_from_bin()
        return result

    def __mul__(self, x):
        """
        Implements polynomial multiplication in GF(2).
        Multiplication is performed through binary polynomial multiplication.
        """
        result = BinPol(0, self.irreducible_polynomial)
        for i, a_bit in enumerate(self.bin):
            for j, b_bit in enumerate(x.bin):
                if a_bit and b_bit:
                    result[i + j] ^= 1
        result.__update_from_bin()
        return result

    def __pow__(self, x):
        """
        Implements polynomial exponentiation in GF(2).
        Uses repeated multiplication with modular reduction.
        """
        result = BinPol(1, self.irreducible_polynomial)
        for _ in range(1, x + 1):
            result = result * BinPol(self.dec)
            if result.irreducible_polynomial and result.grade >= result.irreducible_polynomial.grade:
                result += result.irreducible_polynomial
            result.__update_from_bin()
        return result

    def __update_from_bin(self):
        """Updates decimal and hex representations after binary modifications."""
        self.__remove_most_significant_zeros()
        self.dec = sum([bit << i for i, bit in enumerate(self.bin)])
        self.hex = hex(self.dec)[2:]
        self.grade = len(self.bin) - 1

    def __remove_most_significant_zeros(self):
        """Removes leading zeros from binary representation."""
        last = 0
        for i, bit in enumerate(self.bin):
            if bit:
                last = i
        del self.bin[last + 1:]
def inv_pol(pol, antilog, log):
    """
    Computes the multiplicative inverse of a polynomial in GF(2^8).
    Uses precomputed log and antilog tables for efficient computation.
    
    Args:
        pol: Polynomial to invert
        antilog: Antilogarithm table
        log: Logarithm table
        
    Returns:
        BinPol: Multiplicative inverse of the input polynomial
    """
    if pol.dec == 0:
        return BinPol(0, pol.irreducible_polynomial)
    return BinPol(antilog[0xFF - log[pol.dec].dec].dec, pol.irreducible_polynomial)

def affine_transformation(b):
    """
    Performs the AES affine transformation on a byte.
    This transformation is part of the S-box generation process.
    
    Args:
        b: Input byte as BinPol object
        
    Returns:
        BinPol: Transformed byte
    """
    b1 = BinPol(b.dec, b.irreducible_polynomial)
    c = BinPol(0b01100011)  # Affine constant
    for i in range(8):
        b1[i] = b[i] ^ b[(i + 4) % 8] ^ b[(i + 5) % 8] ^ b[(i + 6) % 8] ^ b[(i + 7) % 8] ^ c[i]
    return b1

def str_16x16(table):
    """
    Formats a 256-byte table as a 16x16 grid for display.
    Used for visualizing S-box and other AES tables.
    
    Args:
        table: 256-byte table to format
        
    Returns:
        str: Formatted string representation
    """
    s = '\t' + '\t'.join(hex(i) for i in range(16)) + '\n'
    for i in range(16):
        s += hex(i) + '\t' + '\t'.join(str(table[i * 16 + j]) for j in range(16)) + '\n'
    return s

def generate():
    """
    Generates the complete set of AES tables including S-box, logarithm,
    and antilogarithm tables. Saves results to files for later use.
    """
    try:
        with open('AES_base.log', 'w') as f:
            # Define core field parameters
            irreducible_polynomial = BinPol(0b100011011)  # x^8 + x^4 + x^3 + x + 1
            primitive = BinPol(3, irreducible_polynomial)  # Generator element
            
            # Generate field tables
            antilog = [primitive**i for i in range(256)]
            log = [BinPol(0, irreducible_polynomial) for _ in range(256)]
            
            # Build logarithm table
            for i, a in enumerate(antilog):
                log[a.dec] = BinPol(i, irreducible_polynomial)
            
            # Generate S-box
            inv = [inv_pol(BinPol(i), antilog, log) for i in range(256)]
            sbox = [affine_transformation(a) for a in inv]
            
            # Log results
            f.write("Generated AES S-box and related tables.\n")
            f.write("Irreducible Polynomial: " + str(irreducible_polynomial) + "\n")
            f.write("S-Box:\n" + str_16x16(sbox) + "\n")
            
            print("Generated S-Box:")
            print(str_16x16(sbox))

    except Exception as e:
        print("Error during AES table generation:", e)
        sys.exit()

    # Save tables for runtime use
    try:
        with open('AES_base.py', 'w') as f:
            s = '''
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Generated AES tables for S-box and other constants

sbox = {0}

'''.format([i.dec for i in sbox])
            f.write(s)
    except Exception as e:
        print("Error saving AES_base.py:", e)
        sys.exit()

def invert_sbox(sbox):
    """
    Creates the inverse S-box from the forward S-box.
    Used in the decryption process.
    
    Args:
        sbox: Forward S-box table
        
    Returns:
        list: Inverse S-box table
    """
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox

class KeyExpansion:
    """
    Handles AES key expansion to generate round keys.
    Implements the key schedule for AES-128.
    """
    
    def __init__(self, key_hex, sbox):
        """
        Initializes key expansion with hex key and S-box.
        
        Args:
            key_hex (str): 128-bit key in hex format
            sbox (list): S-box for byte substitution
        """
        if len(key_hex) != 32:
            raise ValueError("AES key must be 128 bits (32 hex characters).")
        self.sbox = sbox
        self.key = self.hex_to_bytes(key_hex)
        self.round_keys = self.key_expansion(self.key)

    @staticmethod
    def hex_to_bytes(hex_string):
        """Converts hex string to byte array."""
        return [int(hex_string[i:i + 2], 16) for i in range(0, len(hex_string), 2)]

    def sub_word(self, word):
        """Applies S-box substitution to each byte in a word."""
        return [self.sbox[b] for b in word]

    def rot_word(self, word):
        """Performs cyclic left rotation on a word."""
        return word[1:] + word[:1]

    def key_expansion(self, key):
        """
        Expands the initial key into round keys.
        
        Args:
            key (list): Initial 128-bit key as byte array
            
        Returns:
            list: List of round keys
        """
        Nk = 4  # Key length in 32-bit words
        Nb = 4  # Block size in 32-bit words
        Nr = 10  # Number of rounds
        W = [[key[4 * i + j] for j in range(4)] for i in range(Nk)]

        for i in range(Nk, Nb * (Nr + 1)):
            temp = W[i - 1]
            if i % Nk == 0:
                temp = self.sub_word(self.rot_word(temp))
                temp[0] ^= rcon[(i // Nk) - 1]
            W.append([a ^ b for a, b in zip(W[i - Nk], temp)])

        return [sum(W[i:i + Nb], []) for i in range(0, len(W), Nb)]



class MixColumns:
    """
    Implements MixColumns and InvMixColumns transformations for AES.
    These operations provide diffusion in the cipher.
    """
    
    @staticmethod
    def gf_multiply(a, b):
        """
        Performs Galois Field multiplication of two bytes.
        
        Args:
            a, b (int): Bytes to multiply
            
        Returns:
            int: Result of GF(2^8) multiplication
        """
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # AES irreducible polynomial
            b >>= 1
        return p

    @staticmethod
    def mix_columns(state):
        """
        Applies MixColumns transformation to the state matrix.
        Multiplies each column with a fixed polynomial.
        
        Args:
            state (list): Current state matrix
            
        Returns:
            list: Transformed state matrix
        """
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
                new_column.append(val % 256)
            new_state.append(new_column)
        
        return [[new_state[row][col] for row in range(4)] for col in range(4)]

    @staticmethod
    def inv_mix_columns(state):
        """
        Applies inverse MixColumns transformation.
        Uses different coefficients from forward transformation.
        
        Args:
            state (list): Current state matrix
            
        Returns:
            list: Inverse transformed state matrix
        """
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
        
        return [[new_state[row][col] for row in range(4)] for col in range(4)]

class SubBytes:
    """
    Implements SubBytes and InvSubBytes transformations.
    Provides non-linearity in the cipher.
    """
    
    @staticmethod
    def execute(state, sbox):
        """
        Applies S-box substitution to each byte in the state.
        
        Args:
            state (list): Current state matrix
            sbox (list): Substitution box
            
        Returns:
            list: Transformed state matrix
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = sbox[state[i][j]]
        return state

    @staticmethod
    def inv_sub_bytes(state, inv_sbox):
        """
        Applies inverse S-box substitution.
        
        Args:
            state (list): Current state matrix
            inv_sbox (list): Inverse substitution box
            
        Returns:
            list: Inverse transformed state matrix
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = inv_sbox[state[i][j]]
        return state

class ShiftRows:
    """
    Implements ShiftRows and InvShiftRows transformations.
    Provides diffusion by shifting rows of the state matrix.
    """
    
    @staticmethod
    def shift_rows(state):
        """
        Shifts each row i by i positions to the left.
        
        Args:
            state (list): Current state matrix
            
        Returns:
            list: Transformed state matrix
        """
        for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]
        return state

    @staticmethod
    def inv_shift_rows(state):
        """
        Shifts each row i by i positions to the right.
        
        Args:
            state (list): Current state matrix
            
        Returns:
            list: Inverse transformed state matrix
        """
        for r in range(1, 4):
            state[r] = state[r][-r:] + state[r][:-r]
        return state

class AddRoundKey:
    """
    Implements the AddRoundKey transformation.
    Provides key mixing in the cipher.
    """
    
    @staticmethod
    def execute(state, round_key):
        """
        XORs the state matrix with the round key matrix.
        
        Args:
            state (list): Current state matrix
            round_key (list): Current round key
            
        Returns:
            list: XORed state matrix
        """
        round_key_matrix = [
            [round_key[0], round_key[4], round_key[8], round_key[12]],
            [round_key[1], round_key[5], round_key[9], round_key[13]],
            [round_key[2], round_key[6], round_key[10], round_key[14]],
            [round_key[3], round_key[7], round_key[11], round_key[15]]
        ]
        
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key_matrix[i][j]
        
        return state
    
class HexConverter:
    """
    Provides utilities for converting between text and hex representations.
    Handles padding and formatting for AES block size requirements.
    """
    
    @staticmethod
    def text_to_hex_128bit(text):
        """
        Converts text to a 128-bit hex string with padding.
        
        Args:
            text (str): Input text
            
        Returns:
            str: 32-character hex string
        """
        hex_str = text.encode('utf-8').hex()
        
        if len(hex_str) < 32:
            hex_str = hex_str.zfill(32)
        else:
            hex_str = hex_str[:32]
            
        return hex_str
    
    @staticmethod
    def hex_to_text_128bit(hex_str):
        """
        Converts 128-bit hex string back to text.
        
        Args:
            hex_str (str): 32-character hex string
            
        Returns:
            str: Decoded text
        """
        try:
            byte_data = bytes.fromhex(hex_str)
            text = byte_data.decode('utf-8', errors='ignore')
            text = text.replace('\x00', '')
            return text
        except ValueError:
            return ''

class AES:
    """
    Main AES cipher implementation class.
    Handles encryption, decryption, and state visualization.
    """
    
    def __init__(self, key_hex):
        """
        Initializes AES cipher with a key.
        
        Args:
            key_hex (str): 128-bit key in hex format
        """
        self.sbox = self.load_sbox()
        self.inv_sbox = invert_sbox(self.sbox)
        self.key_expansion = KeyExpansion(key_hex, self.sbox)
        self.round_keys = self.key_expansion.round_keys
        self.mix_columns = MixColumns()
        self.inv_mix_columns = MixColumns()
    
    def load_sbox(self):
        """
        Loads the S-box from the generated AES_base module.
        
        Returns:
            list: S-box table
        """
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from AES_base import sbox
            return sbox
        except ImportError as e:
            print(f"Error loading S-box: {e}")
            return None
        
    def state_to_json_matrix(self, state, operation=None, round_num=None):
        """
        Converts state matrix to JSON format for visualization.
        
        Args:
            state (list): Current state matrix
            operation (str, optional): Current operation name
            round_num (int, optional): Current round number
            
        Returns:
            dict: JSON representation of the state
        """
        matrix_data = {
            "matrix": [[f"{cell:02x}" for cell in row] for row in state],
            "formatted": self.state_to_hex(state)
        }
        
        if operation:
            matrix_data["operation"] = operation
        if round_num is not None:
            matrix_data["round"] = round_num
            
        return matrix_data
    
    def matrix_to_state(self, round_key):
        """
        Converts round key array to state matrix format.
        
        Args:
            round_key (list): Round key bytes
            
        Returns:
            list: State matrix format
        """
        state = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = round_key[i + 4*j]
        return state
    
    @staticmethod
    def hex_to_state(hex_string):
        """
        Converts hex string to state matrix.
        
        Args:
            hex_string (str): Input hex string
            
        Returns:
            list: State matrix
        """
        return [[int(hex_string[i*2+j*8:i*2+j*8+2], 16) for j in range(4)] for i in range(4)]

    def state_to_hex(self, state):
        """
        Converts state matrix to formatted hex string.
        
        Args:
            state (list): State matrix
            
        Returns:
            str: Formatted hex string
        """
        hex_state = ""
        for i in range(4):
            hex_state += " ".join([f"{state[i][j]:02x}" for j in range(4)]) + "\n"
        return hex_state
    
    def matrix_to_hex_string_by_column(self, matrix_str):
        """
        Converts matrix string to hex string by column.
        
        Args:
            matrix_str (str): Matrix string representation
            
        Returns:
            str: Hex string
        """
        lines = [line.strip() for line in matrix_str.split('\n') if line.strip()]
        matrix = [line.split() for line in lines]
        result = ''
        for col in range(4):
            for row in range(4):
                result += matrix[row][col]
        return result

    def encrypt(self, plaintext_hex):
        """
        Performs AES encryption with visualization data collection.
        
        Args:
            plaintext_hex (str): Input plaintext in hex format
            
        Returns:
            tuple: (ciphertext, visualization_data)
        """
        states = []
        state = self.hex_to_state(plaintext_hex)
        
        # Record initial state
        states.append({
            "title": "Input",
            "matrices": [
                {
                    "label": "Start of round",
                    "data": [[f"{cell:02x}" for cell in row] for row in state],
                    "tooltip": "Original input text arranged in a 4x4 matrix"
                },
                {
                    "label": "Round Key",
                    "data": [[f"{cell:02x}" for cell in row] for row in self.matrix_to_state(self.round_keys[0])],
                    "tooltip": "Initial round key for AddRoundKey operation"
                }
            ]
        })

        # Initial round
        state = AddRoundKey.execute(state, self.round_keys[0])

        # Main rounds (1-9)
        for round in range(1, 10):
            round_matrices = []
            round_matrices.append({
                "label": "Start of round",
                "data": [[f"{cell:02x}" for cell in row] for row in state],
                "tooltip": f"State after Round {round-1 if round > 1 else 'initial'} AddRoundKey"
            })

            state = SubBytes.execute(state, self.sbox)
            state = ShiftRows.shift_rows(state)
            state = MixColumns.mix_columns(state)
            
            round_matrices.extend([
                {
                    "label": "After SubBytes",
                    "data": [[f"{cell:02x}" for cell in row] for row in state],
                    "tooltip": "Each byte replaced using S-box substitution"
                },
                {
                    "label": "After ShiftRows",
                    "data": [[f"{cell:02x}" for cell in row] for row in state],
                    "tooltip": "Rows shifted cyclically to the left"
                },
                {
                    "label": "After MixColumns",
                    "data": [[f"{cell:02x}" for cell in row] for row in state],
                    "tooltip": "Columns transformed using matrix multiplication"
                },
                {
                    "label": "Round Key",
                    "data": [[f"{cell:02x}" for cell in row] for row in self.matrix_to_state(self.round_keys[round])],
                    "tooltip": f"Round key for Round {round}"
                }
            ])

            state = AddRoundKey.execute(state, self.round_keys[round])
            states.append({"title": f"Round {round}", "matrices": round_matrices})

        # Final round (10)
        final_matrices = []
        final_matrices.append({
            "label": "Start of round",
            "data": [[f"{cell:02x}" for cell in row] for row in state],
            "tooltip": "State after Round 9 AddRoundKey"
        })

        state = SubBytes.execute(state, self.sbox)
        state = ShiftRows.shift_rows(state)
        
        final_matrices.extend([
            {
                "label": "After SubBytes",
                "data": [[f"{cell:02x}" for cell in row] for row in state],
                "tooltip": "Each byte replaced using S-box substitution"
            },
            {
                "label": "After ShiftRows",
                "data": [[f"{cell:02x}" for cell in row] for row in state],
                "tooltip": "Rows shifted cyclically to the left"
            },
            {
                "label": "Round Key",
                "data": [[f"{cell:02x}" for cell in row] for row in self.matrix_to_state(self.round_keys[10])],
                "tooltip": "Round key for Final Round"
            }
        ])

        state = AddRoundKey.execute(state, self.round_keys[10])
        encrypted_hex = self.state_to_hex(state)
        ciphertext = ''.join(char for chars in zip(*[line.split() for line in encrypted_hex.splitlines()]) for char in chars)

        states.append({"title": "Round 10", "matrices": final_matrices})

        visualization_data = {
            "input": {
                "plaintext": plaintext_hex,
                "key": ''.join([f"{byte:02x}" for byte in self.round_keys[0]])
            },
            "rounds": states,
            "output": {
                "ciphertext": ciphertext
            }
        }

        return ciphertext, visualization_data

    def decrypt(self, ciphertext_hex):
        """
        Performs AES decryption with visualization data collection.
        
        Args:
            ciphertext_hex (str): Input ciphertext in hex format
            
        Returns:
            tuple: (plaintext, visualization_data)
        """
        try:
            states = []
            new_cipher_text = self.matrix_to_hex_string_by_column(ciphertext_hex) if '\n' in ciphertext_hex else ciphertext_hex
            state = self.hex_to_state(new_cipher_text)

            # Initial state
            states.append({
                "title": "Input",
                "matrices": [
                    {
                        "label": "Start of round",
                        "data": [[f"{cell:02x}" for cell in row] for row in state],
                        "tooltip": "Original ciphertext arranged in a 4x4 matrix"
                    }
                ]
            })

            # Initial AddRoundKey
            state = AddRoundKey.execute(state, self.round_keys[10])
            states[-1]["matrices"].append({
                "label": "After AddRoundKey",
                "data": [[f"{cell:02x}" for cell in row] for row in state],
                "tooltip": "State after initial round key addition"
            })

            # Main rounds (9 to 1)
            for round_num in range(9, 0, -1):
                round_matrices = []
                
                state = ShiftRows.inv_shift_rows(state)
                state = SubBytes.inv_sub_bytes(state, self.inv_sbox)
                state = AddRoundKey.execute(state, self.round_keys[round_num])
                state = MixColumns.inv_mix_columns(state)

                round_matrices.extend([
                    {
                        "label": "After InvShiftRows",
                        "data": [[f"{cell:02x}" for cell in row] for row in state],
                        "tooltip": "State after inverse shift rows operation"
                    },
                    {
                        "label": "After InvSubBytes",
                        "data": [[f"{cell:02x}" for cell in row] for row in state],
                        "tooltip": "State after inverse S-box substitution"
                    },
                    {
                        "label": "After AddRoundKey",
                        "data": [[f"{cell:02x}" for cell in row] for row in state],
                        "tooltip": "State after round key addition"
                    },
                    {
                        "label": "After InvMixColumns",
                        "data": [[f"{cell:02x}" for cell in row] for row in state],
                        "tooltip": "State after inverse mix columns operation"
                    }
                ])

                states.append({"title": f"Round {round_num}", "matrices": round_matrices})

            # Final round
            final_matrices = []
            state = ShiftRows.inv_shift_rows(state)
            state = SubBytes.inv_sub_bytes(state, self.inv_sbox)
            state = AddRoundKey.execute(state, self.round_keys[0])

            final_matrices.extend([
                {
                    "label": "After InvShiftRows",
                    "data": [[f"{cell:02x}" for cell in row] for row in state],
                    "tooltip": "State after final inverse shift rows"
                },
                {
                    "label": "After InvSubBytes",
                    "data": [[f"{cell:02x}" for cell in row] for row in state],
                    "tooltip": "State after final inverse S-box substitution"
                },
                {
                    "label": "After AddRoundKey",
                    "data": [[f"{cell:02x}" for cell in row] for row in state],
                    "tooltip": "Final decrypted state"
                }
            ])

            states.append({"title": "Final Round", "matrices": final_matrices})

            decrypted_hex = self.state_to_hex(state)
            plaintext = ''.join(char for chars in zip(*[line.split() for line in decrypted_hex.splitlines()]) for char in chars)
            plain_text = HexConverter.hex_to_text_128bit(plaintext)

            visualization_data = {
                "input": {
                    "ciphertext": ciphertext_hex,
                    "key": ''.join([f"{byte:02x}" for byte in self.round_keys[10]])
                },
                "rounds": states,
                "output": {
                    "plaintext": plaintext
                }
            }

            return plain_text, visualization_data

        except Exception as e:
            return None, {"error": f"Decryption failed: {str(e)}"}

# Flask API routes
def initialize_aes():
    """
    Initializes AES system by generating necessary tables.
    Must be called before starting the API server.
    
    Returns:
        bool: Success status
    """
    try:
        generate()
        return True
    except Exception as e:
        print(f"Failed to initialize AES: {e}")
        return False

@app.route('/api/encrypt', methods=['POST'])
def encrypt_api():
    """API endpoint for encryption."""
    try:
        data = request.get_json()
        plaintext = data.get('plaintext')
        key_hex = data.get('key')
        
        if not plaintext or not key_hex:
            return jsonify({
                "status": "error",
                "message": "Missing plaintext or key"
            }), 400
        
        plaintext_hex = HexConverter.text_to_hex_128bit(plaintext)
        aes = AES(key_hex)
        ciphertext, visualization_data = aes.encrypt(plaintext_hex)
        
        return jsonify({
            "status": "success",
            "ciphertext": ciphertext,
            "visualization": visualization_data
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_api():
    """API endpoint for decryption."""
    try:
        data = request.get_json()
        ciphertext = data.get('ciphertext')
        key_hex = data.get('key')
        
        if not ciphertext or not key_hex:
            return jsonify({
                "status": "error",
                "message": "Missing ciphertext or key"
            }), 400
        
        aes = AES(key_hex)
        decrypted_text, visualization_data = aes.decrypt(ciphertext)
        
        if decrypted_text is None:
            return jsonify({
                "status": "error",
                "message": visualization_data.get("error", "Decryption failed")
            }), 400

        return jsonify({
            "status": "success",
            "plaintext": decrypted_text,
            "visualization": visualization_data
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/test', methods=['GET'])
def test_api():
    """Simple endpoint to verify API status."""
    return jsonify({
        "status": "success",
        "message": "AES API is running"
    })

if __name__ == "__main__":
    if initialize_aes():
        print("AES initialized successfully. Starting API server...")
        app.run(debug=True, port=5000)
    else:
        print("Failed to initialize AES")
        sys.exit(1)