import streamlit as st
import rsa

def encrypt(message, public_key):
    # Encrypt the message using the public key
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    return encrypted_message

def decrypt(encrypted_message, private_key):
    # Decrypt the encrypted message using the private key
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    return decrypted_message.decode()

def asymmetric_key_cryptography():
    st.title("Asymmetric Key Cryptography")

    # User input for public key
    public_key_input = st.text_input("Enter public key (n, e)", help="Format: n, e")

    # User input for private key
    private_key_input = st.text_input("Enter private key (n, d)", help="Format: n, d")

    if public_key_input and private_key_input:
        try:
            # Parse user input to extract public and private keys
            public_key = tuple(map(int, public_key_input.strip().split(',')))
            private_key = tuple(map(int, private_key_input.strip().split(',')))

            # Example usage
            message = st.text_input("Enter a message to encrypt")

            if st.button("Encrypt"):
                # Encrypt the message using the user-provided public key
                encrypted_message = encrypt(message, public_key)
                st.write("Encrypted message:", encrypted_message.hex())

            encrypted_input = st.text_input("Enter encrypted message")

            if st.button("Decrypt"):
                # Decrypt the encrypted message using the user-provided private key
                try:
                    decrypted_message = decrypt(bytes.fromhex(encrypted_input), private_key)
                    st.write("Decrypted message:", decrypted_message)
                except:
                    st.error("Invalid encrypted message")
        except ValueError:
            st.error("Invalid key format. Please enter keys in the correct format (n, e) or (n, d)")

if __name__ == "__main__":
    asymmetric_key_cryptography()
