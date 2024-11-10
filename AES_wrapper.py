from flask import Flask, jsonify
from flask_cors import CORS  # You'll need to install this: pip install flask-cors
import sys
import os
from AES_SystemModel_v2 import AES  # Import your existing AES class

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

class AESVisualizer:
    def __init__(self):
        self.key_hex = "5468617473206D79204B756E67204675"  # Default key
        self.aes = AES(self.key_hex)
        self.current_state = []
        self.rounds_data = []

    def capture_state(self, state, stage, round_number):
        # Convert state matrix to formatted string
        state_str = '\n'.join([' '.join([f"{cell:02x}" for cell in row]) for row in state])
        
        # Add to rounds data
        if round_number >= len(self.rounds_data):
            self.rounds_data.append({})
        self.rounds_data[round_number][stage] = state_str

    def encrypt(self, plaintext_hex):
        self.rounds_data = []  # Reset rounds data
        
        # Initial state
        state = self.aes.hex_to_state(plaintext_hex)
        self.capture_state(state, 'initial_state', 0)
        
        # Initial AddRoundKey
        state = AddRoundKey.execute(state, self.aes.round_keys[0])
        self.capture_state(state, 'after_add_round_key', 0)
        
        # Main rounds
        for round in range(1, 10):
            # SubBytes
            state = SubBytes.execute(state, self.aes.sbox)
            self.capture_state(state, 'after_subbytes', round)
            
            # ShiftRows
            state = ShiftRows.shift_rows(state)
            self.capture_state(state, 'after_shiftrows', round)
            
            # MixColumns
            state = MixColumns.mix_columns(state)
            self.capture_state(state, 'after_mixcolumns', round)
            
            # AddRoundKey
            state = AddRoundKey.execute(state, self.aes.round_keys[round])
            self.capture_state(state, 'after_add_round_key', round)

        # Final round
        state = SubBytes.execute(state, self.aes.sbox)
        self.capture_state(state, 'after_subbytes', 10)
        
        state = ShiftRows.shift_rows(state)
        self.capture_state(state, 'after_shiftrows', 10)
        
        state = AddRoundKey.execute(state, self.aes.round_keys[10])
        self.capture_state(state, 'final_state', 10)
        
        return self.rounds_data

aes_visualizer = AESVisualizer()

@app.route('/init', methods=['GET'])
def initialize():
    return jsonify({'status': 'ready'})

@app.route('/encrypt/<plaintext_hex>', methods=['GET'])
def encrypt(plaintext_hex):
    try:
        rounds_data = aes_visualizer.encrypt(plaintext_hex)
        return jsonify({
            'status': 'success',
            'rounds': rounds_data
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True, port=5000)