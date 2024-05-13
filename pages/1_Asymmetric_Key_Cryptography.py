import streamlit as st
import base64
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from streamlit.logger import get_logger
from tinyec import registry
from hashlib import sha256

LOGGER = get_logger(__name__)

st.set_page_config(
    page_title="Asymmetric Key Cryptography",
    page_icon="🔑",
)

def RSA_Cipher():
    st.header('RSA Encryption/Decryption', divider='rainbow')
    class SessionState:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    def generate_key_pair(key_size):
        try:
            key = RSA.generate(key_size)
            private_key = key.export_key(format='PEM')
            public_key = key.publickey().export_key(format='PEM')
            return private_key, public_key
        except ValueError as e:
            st.error(f"Error generating key pair: {e}")
            return None, None

    def rsa_encrypt(message, public_key, cipher_type):
        try:
            key = RSA.import_key(public_key)
            if cipher_type == "RSA, ECB, PKCS1Padding":
                cipher = PKCS1_v1_5.new(key)
            elif cipher_type == "RSA, ECB, OAEPWithSHA, 1AndMGF1Padding":
                cipher = PKCS1_OAEP.new(key)
            else:
                cipher = PKCS1_v1_5.new(key)
            encrypted_message = cipher.encrypt(message)
            return base64.b64encode(encrypted_message)
        except ValueError as e:
            st.error(f"Error encrypting message: {e}")
            return None

    def rsa_decrypt(encrypted_message, private_key, cipher_type):
        try:
            key = RSA.import_key(private_key)
            cipher = None
            
            if cipher_type == "RSA, ECB, PKCS1Padding":
                cipher = PKCS1_v1_5.new(key)
            elif cipher_type == "RSA, ECB, OAEPWithSHA, 1AndMGF1Padding":
                cipher = PKCS1_OAEP.new(key)
            elif cipher_type == "RSA, ECB, OAEPWithSHA, 256AndMGF1Padding":
                cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256, mgf=MGF1)
            else:
                cipher = PKCS1_v1_5.new(key)

            if cipher_type.startswith("RSA, ECB, OAEPWithSHA"):
                decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))
            else:
                decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message), sentinel=b"")
            return decrypted_message
        except ValueError as e:
            st.error(f"Error decrypting message: {e}")
            return None

    def main():
        mode = st.selectbox("Select Mode:", ["Encrypt", "Decrypt"])

        if not hasattr(st.session_state, "keys_generated"):
            st.session_state.keys_generated = False
            st.session_state.private_key = None
            st.session_state.public_key = None

        if mode == "Encrypt":
            key_sizes = [1024, 2048, 3072, 4096]
            key_size = st.selectbox("Select RSA Key Size", key_sizes)

            if st.button("Generate RSA Key Pair") or not st.session_state.keys_generated:
                private_key, public_key = generate_key_pair(key_size)
                if private_key is not None and public_key is not None:
                    st.session_state.private_key = private_key
                    st.session_state.public_key = public_key
                    st.session_state.keys_generated = True

            if st.session_state.public_key and st.session_state.private_key is not None:
                st.text("Public Key (X.509 Format):")
                st.text(st.session_state.public_key.decode())  # decode bytes to string
                st.text("Private Key (PKCS8 Format):")
                st.text(st.session_state.private_key.decode())  # decode bytes to string

            rsa_mode = st.radio("RSA Key Type:", ["Public Key", "Private Key"])

            cipher_types = ["RSA", "RSA, ECB, PKCS1Padding", "RSA, ECB, OAEPWithSHA, 1AndMGF1Padding"]
            cipher_type = st.selectbox("Select Cipher Type:", cipher_types)

            if rsa_mode == "Public Key":
                message_encrypt = st.text_input("Enter Plain Text to Encrypt")
                if st.button("Encrypt"):
                    if message_encrypt.strip() == "":
                        st.warning("Please enter some text to encrypt.")
                    else:
                        encrypted_message = rsa_encrypt(message_encrypt.encode(), st.session_state.public_key, cipher_type)
                        if encrypted_message is not None:
                            st.text("Encrypted Output (Base64):")
                            st.text(encrypted_message.decode())  # decode bytes to string
            else:
                st.warning("You're in Encrypt mode. Please select Public Key for encryption.")

        else:
            if st.session_state.private_key is not None:
                cipher_types = ["RSA", "RSA, ECB, PKCS1Padding", "RSA, ECB, OAEPWithSHA, 1AndMGF1Padding"]
                cipher_type = st.selectbox("Select Cipher Type:", cipher_types)
                message_decrypt = st.text_input("Enter Encrypted Text to Decrypt (Base64)")
                if st.button("Decrypt"):
                    decrypted_message = rsa_decrypt(message_decrypt.encode(), st.session_state.private_key, cipher_type)
                    if decrypted_message is not None:
                        st.text("Decrypted Output:")
                        st.text(decrypted_message.decode())  # decode bytes to string
            else:
                st.error("Please generate RSA key pair first.")

    if __name__ == "__main__":
        main()

def DFA_Cipher():
    st.header('Diffie-Hellman Encryption/Decryption App', divider='rainbow')

    from sympy import isprime, primerange

    def calculate_public_key(prime, generator, private_key):
        public_key = pow(generator, private_key, prime)
        return public_key

    def calculate_shared_secret(private_key, received_public_key, prime):
        shared_secret = pow(received_public_key, private_key, prime)
        return shared_secret

    def encrypt_message(message, shared_secret):
        # Placeholder encryption
        encrypted_message = ''.join(chr(ord(c) + shared_secret) for c in message)
        return encrypted_message

    def decrypt_message(encrypted_message, shared_secret):
        # Placeholder decryption
        decrypted_message = ''.join(chr(ord(c) - shared_secret) for c in encrypted_message)
        return decrypted_message

    def main():
        st.title("Diffie-Hellman Key Exchange")

        # Column 1
        col1, col2 = st.columns(2)
        with col1:
            st.title("Key Generation")
            prime = st.number_input("Enter a prime number:", min_value=3, step=1)
            if not isprime(prime):
                st.warning("Please enter a prime number.")
                return

            max_generator = prime - 1 if prime > 2 else 1
            generator = st.number_input("Enter generator:", min_value=2, max_value=max_generator, step=1)
            if generator not in primerange(2, prime):
                st.warning("Please enter a primitive root of the inputted prime number.")
                return

            private_key = st.number_input("Enter private key:", min_value=5, step=1)

            public_key = calculate_public_key(prime, generator, private_key)
            st.write("Public Key:", public_key)
            st.write("Private Key:", private_key)

        # Column 2
        with col2:
            message = st.text_area("Type a message:")
            send_button = st.button("Send")

            if send_button:
                # Encrypt the message
                received_public_key_input = st.text_input("Enter Received public key:")
                if received_public_key_input.strip() == "":
                    st.warning("Please enter a valid public key.")
                    return
                shared_secret = calculate_shared_secret(private_key, int(received_public_key_input), prime)
                encrypted_message = encrypt_message(message, shared_secret)
                st.write("Encrypted Message:", encrypted_message)

            received_message = st.text_input("Enter Received message (encrypted message):")
            receive_button = st.button("Receive")

            if receive_button:
                # Decrypt the received message
                sender_private_key_input = st.text_input("Enter Sender's private key:")
                if sender_private_key_input.strip() == "":
                    st.warning("Please enter a valid private key.")
                    return
                shared_secret = calculate_shared_secret(private_key, int(sender_private_key_input), prime)
                decrypted_message = decrypt_message(received_message, shared_secret)
                st.write("Decrypted Message:", decrypted_message)

    if __name__ == "__main__":
        main()



    




if __name__ == "__main__":
    tab1, tab2 = st.tabs(["RSA Cipher", "Diffie Hellman Cipher"])

    with tab1:
        RSA_Cipher()
    
    with tab2:
        DFA_Cipher()
