import streamlit as st
import rsa

def generate_keys():
    # Generate public and private keys
    (public_key, private_key) = rsa.newkeys(512)  # Adjust key size according to your requirements
    return public_key, private_key

def encrypt(message, public_key):
    # Encrypt the message using the public key
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    return encrypted_message

def decrypt(encrypted_message, private_key):
    # Decrypt the encrypted message using the private key
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    return decrypted_message.decode()

def asymmetric_key_cryptography():
    # Generate keys
    public_key, private_key = generate_keys()

    # Example usage
    message = st.text_input("Enter a message to encrypt")

    if st.button("Encrypt"):
        # Encrypt the message using the public key
        encrypted_message = encrypt(message, public_key)
        st.write("Encrypted message:", encrypted_message.hex())

    encrypted_input = st.text_input("Enter encrypted message")

    if st.button("Decrypt"):
        # Decrypt the encrypted message using the private key
        try:
            decrypted_message = decrypt(bytes.fromhex(encrypted_input), private_key)
            st.write("Decrypted message:", decrypted_message)
        except:
            st.error("Invalid encrypted message")

if __name__ == "__main__":
    st.title("Asymmetric Key Cryptography")
    asymmetric_key_cryptography()
