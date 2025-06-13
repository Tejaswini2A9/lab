
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def aes_encrypt_decrypt(data: str, key: bytes):
    """AES encryption and decryption."""
    # AES requires a 16-byte, 24-byte, or 32-byte key
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Initialization vector
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    
    # Decrypt
    decipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(decipher.decrypt(encrypted_data), AES.block_size).decode()
    
    return encrypted_data, decrypted_data

def des_encrypt_decrypt(data: str, key: bytes):
    """DES encryption and decryption."""
    # DES requires an 8-byte key
    cipher = DES.new(key, DES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data.encode(), DES.block_size))
    
    # Decrypt
    decipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = unpad(decipher.decrypt(encrypted_data), DES.block_size).decode()

    return encrypted_data, decrypted_data

if __name__ == "__main__":
    data = input()
    
    # AES Example
    aes_key = get_random_bytes(32)  # 16-byte key for AES
    aes_encrypted, aes_decrypted = aes_encrypt_decrypt(data, aes_key)
    print("AES Encrypted:", aes_encrypted)
    print("AES Decrypted:", aes_decrypted)

    # DES Example
    des_key = get_random_bytes(8)  # 8-byte key for DES
    des_encrypted, des_decrypted = des_encrypt_decrypt(data, des_key)
    print("DES Encrypted:", des_encrypted)
    print("DES Decrypted:", des_decrypted)
