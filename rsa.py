from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def rsa(message):
    print("===== RSA DEMONSTRATION =====\n")
    message = message.encode()
    
    key = RSA.generate(2048)
    private = key.export_key()
    public = key.public_key().export_key()

    encrypter = PKCS1_OAEP.new(RSA.import_key(public))
    encrypted_msg = encrypter.encrypt(message)
    print("===== Encrypted Message =====")
    print(encrypted_msg)

    decrypter = PKCS1_OAEP.new(RSA.import_key(private))
    decrypted_msg = decrypter.decrypt(encrypted_msg)
    print("\n===== Decrypted Message =====")
    print(decrypted_msg)

rsa("helllo")
