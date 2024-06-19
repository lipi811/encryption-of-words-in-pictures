from flask import Flask, request, render_template, jsonify, redirect, url_for
import cv2
import numpy as np
import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

app = Flask(__name__)

def generate_key(password):
    """Generate a key from a password using Scrypt."""
    password = password.encode()  # Convert to bytes
    salt = b'\x00'*16  # A fixed salt; ideally, use a unique salt per password
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_message(message, password):
    """Encrypt the message using the password."""
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, password):
    """Decrypt the message using the password."""
    key = generate_key(password)
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message)
    return decrypted_message.decode()

def text_to_binary(text):
    """Converts a string of text to binary."""
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    return binary_text

def binary_to_text(binary):
    """Converts binary string to text."""
    text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))
    return text

def encode_message(image_path, message, output_path):
    """Encodes a message into an image."""
    image = cv2.imread(image_path)
    binary_message = text_to_binary(message) + '1111111111111110'  # End of message delimiter
    data_index = 0

    for row in image:
        for pixel in row:
            for i in range(3):  # Iterate over RGB channels
                if data_index < len(binary_message):
                    pixel[i] = int(bin(pixel[i])[2:-1] + binary_message[data_index], 2)
                    data_index += 1

    cv2.imwrite(output_path, image)

def decode_message(image_path):
    """Decodes a message from an image."""
    image = cv2.imread(image_path)
    binary_message = ""
    for row in image:
        for pixel in row:
            for i in range(3):  # Iterate over RGB channels
                binary_message += bin(pixel[i])[-1]

    # Split by the delimiter
    binary_message = binary_message.split('1111111111111110')[0]
    message = binary_to_text(binary_message)
    return message

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    input_image = request.files['inputImage']
    message = request.form['message']
    password = request.form['password']
    output_image_path = request.form['outputImage']

    input_image_path = os.path.join('uploads', input_image.filename)
    input_image.save(input_image_path)

    encrypted_message = encrypt_message(message, password)
    encode_message(input_image_path, encrypted_message.decode('utf-8'), output_image_path)
    return redirect(url_for('index', message='encoded'))

@app.route('/decode', methods=['POST'])
def decode():
    encoded_image = request.files['encodedImage']
    password = request.form['password']

    encoded_image_path = os.path.join('uploads', encoded_image.filename)
    encoded_image.save(encoded_image_path)

    encoded_message = decode_message(encoded_image_path)
    try:
        decrypted_message = decrypt_message(encoded_message.encode('utf-8'), password)
        return jsonify({'message': decrypted_message})
    except Exception as e:
        return jsonify({'message': 'Incorrect password or corrupted image'}), 400

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
