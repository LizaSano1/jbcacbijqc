import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from tinyec import registry

curve = registry.get_curve('brainpoolP256r1')
private_key = secrets.randbelow(curve.field.n)
public_key = private_key * curve.g

def encrypt_message(message, private_key):
    shared_key = secrets.token_bytes(32)
    public_key = (private_key * curve.g).to_bytes(65, 'big')
    encryptor = Cipher(algorithms.AES(shared_key), modes.CBC(secrets.token_bytes(16)), backend=default_backend()).encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize(), public_key, shared_key

def decrypt_message(encrypted_message, private_key, shared_key):
    decryptor = Cipher(algorithms.AES(shared_key), modes.CBC(encrypted_message[:16]), backend=default_backend()).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    padded_data = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    return unpadder.update(padded_data) + unpadder.finalize().decode()

def encrypt_id(id):
    encrypted_id = encrypt_message(str(id).encode(), private_key)[0]
    return encrypted_id

def decrypt_id(encrypted_id):
    private_key = 123456  # Replace this with your actual private key
    id = decrypt_message(encrypted_id, private_key, (private_key * public_key).to_bytes(32, 'big'))
    return int(id)

message = input("Enter the message to encrypt: ")
id = generate_id()
encrypted_message, public_key, shared_key = encrypt_message(message.encode(), private_key)
encrypted_id = encrypt_id(id)
id_encrypted_in_message = encrypted_message[-16:]
encrypted_message = encrypted_message[:-16]
print("Encrypted message: ", encrypted_message)
decrypted_message = decrypt_message(encrypted_message + id_encrypted_in_message, private_key, shared_key)
decrypted_id = decrypt_id(id_encrypted_in_message)
print("Decrypted message: ", decrypted_message)
print("Decrypted id: ", decrypted_id)
if id == decrypted_id:
    print("IDs match")
else:
    print("IDs do not match")