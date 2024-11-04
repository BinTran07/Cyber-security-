from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_key_pair():
    """Generate RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    """Encrypt a message using the provided public key."""
    rsa_public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    """Decrypt an encrypted message using the provided private key."""
    rsa_private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

def main():
    # Generate RSA key pair
    private_key, public_key = generate_key_pair()
    print("Private Key:", private_key.decode())
    print("Public Key:", public_key.decode())

    # Message to encrypt
    message = "This is a secret message"
    print("Original Message:", message)

    # Encrypt the message
    encrypted_message = encrypt_message(message, public_key)
    print("Encrypted Message:", encrypted_message)

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, private_key)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()

