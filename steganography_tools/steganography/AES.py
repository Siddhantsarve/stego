from Cryptodome.Cipher import AES



def pad_message(message):
    # Pad the message to be a multiple of 16 bytes
    pad_length = 16 - (len(message) % 16)
    padded_message = message + bytes([pad_length] * pad_length)
    return padded_message


def unpad_message(padded_message):
    # Remove the padding from the decrypted message
    pad_length = padded_message[-1]
    message = padded_message[:-pad_length]
    return message.decode()


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(pad_message(message))
    return encrypted_message


def decrypt_message(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(ciphertext)
    return unpad_message(decrypted_message)

