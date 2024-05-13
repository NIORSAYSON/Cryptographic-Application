import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)

st.set_page_config(
    page_title="Symmetric Key Cryptography",
    page_icon="🔑",
)

def XOR_Cipher():
    st.header('XOR Encryption and Decryption', divider='rainbow')

    def xor_encrypt(plaintext, key):
        """Encrypts plaintext using XOR cipher with the given key."""
        ciphertext = bytearray()
        for i in range(len(plaintext)):
            plaintext_byte = plaintext[i]
            key_byte = key[i % len(key)]
            cipher_byte = plaintext_byte ^ key_byte
            ciphertext.append(cipher_byte)
        return ciphertext

    def xor_decrypt(ciphertext, key):
        """Decrypts ciphertext using XOR cipher with the given key."""
        return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption
    
    # Streamlit UI for Encryption
    def encryption_section(plaintext_input):
        st.subheader("XOR Encryption")

        key = st.text_input("Encryption Key", key="encrypt_key")

        if st.button("Encrypt", key="encrypt_btn"):
            if plaintext_input and key.strip():
                if len(plaintext_input) >= len(key):
                    try:
                        ciphertext = xor_encrypt(plaintext_input.encode(), key.encode())
                        st.write("Ciphertext:", ciphertext.decode())
                    except:
                        st.error("Invalid Key!")
                else:
                    st.error("Plaintext length should be equal or greater than the length of key")
            else:
                if not plaintext_input and not key.strip():
                    st.error("Please input a plaintext and key.")
                elif not plaintext_input:
                    st.error("Please input a plaintext or upload a file.")
                elif not key.strip():
                    st.error("Please input a key.")

    # Streamlit UI for Decryption
    def decryption_section(ciphertext_input):
        st.subheader("XOR Decryption")

        key = st.text_input("Decryption Key", key="decrypt_key")

        if st.button("Decrypt", key="decrypt_btn"):
            if ciphertext_input and key.strip():
                if len(ciphertext_input) >= len(key):
                    try:
                        plaintext = xor_decrypt(ciphertext_input.encode(), key.encode()).decode()
                        st.write("Decrypted Plaintext:", plaintext)
                    except:
                        st.error("Invalid Key!")
                else:
                    st.error("Ciphertext length should be equal or greater than the length of key")
            else:
                if not ciphertext_input and not key.strip():
                    st.error("Please input a ciphertext and key.")
                elif not ciphertext_input:
                    st.error("Please input a ciphertext.")
                elif not key.strip():
                    st.error("Please input a key.")

    option = st.radio("Select Input Type", ("Text", "File"))

    if option == "Text":
        plaintext_input = st.text_input("Plaintext")
        encryption_section(plaintext_input)
        st.write("---")
        ciphertext_input = st.text_input("Ciphertext")
        decryption_section(ciphertext_input)
    else:
       # File upload
        uploaded_file = st.file_uploader("Upload plaintext file", type=["txt"])
        if uploaded_file:
            file_content = uploaded_file.read().decode()
            # Encryption section
            encryption_section(file_content)
            st.write("---")
            st.subheader("XOR Decryption")
            key = st.text_input("Decryption Key", key="decrypt_key")
            if st.button("Decrypt", key="decrypt_btn"):
                st.write("Decrypted Plaintext:", file_content)

def Caesar_Cipher():
    st.header('Caesar Cipher Encryption and Decryption', divider='rainbow')
    
    def encrypt_decrypt(text, shift_keys, ifdecrypt):
        """
        Encrypts or decrypts a text using Caesar Cipher with a list of shift keys.
        Args:
            text: The text to encrypt or decrypt, or the content of the file.
            shift_keys: A list of integers representing the shift values for each character.
            ifdecrypt: Flag indicating whether to decrypt or encrypt.
        Returns:
            A string containing the encrypted text if encrypting, or plain text if decrypting.
        """
        res = ""
        for i, character in enumerate(text):
            shift_index = shift_keys[i % len(shift_keys)]
            if ifdecrypt:
                res += chr((ord(character) - shift_index - 32) % 94 + 32)
            else:
                res += chr((ord(character) + shift_index - 32 + 94) % 94 + 32)
            st.write(i, character, shift_index, res[i])
            
        st.write("-" * 10)
            
        return res


    option = st.radio("Select Input Type:", ("Text", "File"))

    if option == "Text":
        text = st.text_input("Text")
        shift_keys_input = st.text_input("Shift Keys")
        if st.button("Submit", key="clk_btn1"):
            try:
                shift_keys = list(map(int, shift_keys_input.split()))
                if not text.strip() and not shift_keys_input.strip():
                    st.error("Please input a text and shift keys.")
                elif not text.strip():
                    st.error("Please input a text.")
                elif not shift_keys_input.strip():
                    st.error("Please input shift keys.")
                elif not all(isinstance(key, int) for key in shift_keys):
                    st.error("Please enter an integer in shift keys.")
                else:
                    st.write("Text:", text)
                    st.write("Shift keys:", ' '.join(map(str, shift_keys)))
                    col1, col2 = st.columns(2)

                    with col1:
                        encrypted_text = encrypt_decrypt(text, shift_keys, ifdecrypt=False)
                        st.write("Cipher:", encrypted_text)
                    with col2:
                        decrypted_text = encrypt_decrypt(encrypted_text, shift_keys, ifdecrypt=True)
                        st.write("Decrypted text:", decrypted_text)

            except:
                st.error("Shift keys should be integers!")

    else:
        # File upload
        uploaded_file = st.file_uploader("Upload plaintext file", type=["txt"])
        if uploaded_file:
            file_content = uploaded_file.read().decode()
            shift_keys_input = st.text_input("Shift Keys")
            if st.button("Submit", key="clk_btn2"):
                try:
                    shift_keys = list(map(int, shift_keys_input.split()))
                    if not shift_keys_input.strip():
                        st.error("Please input shift keys.")
                    elif not all(isinstance(key, int) for key in shift_keys):
                        st.error("Please enter an integer in shift keys.")
                    else:
                        st.write("Shift keys:", ' '.join(map(str, shift_keys)))
                        col1, col2 = st.columns(2)

                        with col1:
                            encrypted_text = encrypt_decrypt(file_content, shift_keys, ifdecrypt=False)
                            st.write("Cipher:", encrypted_text)
                        with col2:
                            decrypted_text = encrypt_decrypt(encrypted_text, shift_keys, ifdecrypt=True)
                            st.write("Decrypted text:", decrypted_text)

                except:
                    st.error("Shift keys should be integers!")


def Block_Cipher():
    st.header('Block Cipher Encryption and Decryption', divider='rainbow') 
  
    def pad(data, block_size):
        padding_length = block_size - len(data) % block_size
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    def xor_encrypt_block(plaintext_block, key):
        encrypted_block = b''
        for i in range(len(plaintext_block)):
            encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
        return encrypted_block

    def xor_decrypt_block(ciphertext_block, key):
        return xor_encrypt_block(ciphertext_block, key)

    def xor_encrypt(plaintext, key, block_size):
        encrypted_data = b''
        padded_plaintext = pad(plaintext, block_size)
        for i in range(0, len(padded_plaintext), block_size):
            plaintext_block = padded_plaintext[i:i+block_size]
            encrypted_block = xor_encrypt_block(plaintext_block, key)
            encrypted_data += encrypted_block
        return encrypted_data

    def xor_decrypt(ciphertext, key, block_size):
        decrypted_data = b''
        for i in range(0, len(ciphertext), block_size):
            ciphertext_block = ciphertext[i:i+block_size]
            decrypted_block = xor_decrypt_block(ciphertext_block, key)
            decrypted_data += decrypted_block
        unpadded_decrypted_data = unpad(decrypted_data)
        return unpadded_decrypted_data

    option = st.radio("Select Type:", ("Text", "File"))

    if option == "Text":
        plaintext_input = st.text_area("Plain text")
        key_input = st.text_input("Key Byte")
        block_size_input = st.text_input("Block Size")

        if st.button("Submit", key="clk_btn3"):
            if not plaintext_input.strip() or not key_input.strip() or not block_size_input.strip():
                st.error("Please input the Plain text, Key, and Block Size.")
            else:
                try:
                    plaintext = bytes(plaintext_input.encode())
                    key = bytes(key_input.encode())
                    block_size = int(block_size_input)
                    if block_size not in [8, 16, 32, 64, 128]:
                        st.error("Block size must be one of 8, 16, 32, 64, or 128 bytes")
                    else:
                        padded_key = pad(key, block_size)
                        encrypted_data = xor_encrypt(plaintext, padded_key, block_size)
                        decrypted_data = xor_decrypt(encrypted_data, padded_key, block_size)
                        
                        st.write("\nOriginal plaintext:", plaintext_input)
                        st.write("Key byte      :", key_input)
                        st.write("Key hex       :", key.hex())
                        st.write("Encrypted data:", encrypted_data.hex())
                        st.write("Decrypted data:", decrypted_data.decode())
                except ValueError:
                    st.error("Block Size should be an integer.")
                    st.error("Please input a valid Block Size.")
                    st.error("Block size must be one of 8, 16, 32, 64, or 128 bytes.")

    else:
        uploaded_file = st.file_uploader("Upload plaintext file", type=["txt"])
        if uploaded_file:
            file_content = uploaded_file.read()
            key_input = st.text_input("Key Byte")
            block_size_input = st.text_input("Block Size")

            if st.button("Submit", key="clk_btn3"):
                if not key_input.strip() or not block_size_input.strip():
                    st.error("Please input the Key and Block Size.")
                else:
                    try:
                        key = bytes(key_input.encode())
                        block_size = int(block_size_input)
                        if block_size not in [8, 16, 32, 64, 128]:
                            st.error("Block size must be one of 8, 16, 32, 64, or 128 bytes")
                        else:
                            padded_key = pad(key, block_size)
                            encrypted_data = xor_encrypt(file_content, padded_key, block_size)
                            decrypted_data = xor_decrypt(encrypted_data, padded_key, block_size)
                            
                            st.write("\nOriginal plaintext:", file_content.decode())
                            st.write("Key byte      :", key_input)
                            st.write("Key hex       :", key.hex())
                            st.write("Encrypted data:", encrypted_data.hex())
                            st.write("Decrypted data:", decrypted_data.decode())
                    except ValueError:
                        st.error("Block Size should be an integer.")
                        st.error("Please input a valid Block Size.")
                        st.error("Block size must be one of 8, 16, 32, 64, or 128 bytes.")


# st.write(b'Hello Bob, this '.hex())




          


if __name__ == "__main__":
    # add_selectbox = st.sidebar.selectbox(
    #     "Types Of Cryptography",
    #     ("Symmetric Key Cryptography", "Asymmetric Key Cryptography", "Hash Functions")
    # )

    tab1, tab2, tab3 = st.tabs(["XOR Cipher", "Caesar Cipher", "Block Cipher"])

    with tab1:
        XOR_Cipher()
    
    with tab2:
        Caesar_Cipher()

    # with tab4:
    #     Primitive_Root()
    
    with tab3:
        Block_Cipher()
      
    # col1, col2, col3, col4, col5 = st.columns(5)

    # with col1:
    #   st.page_link("Home.py", label="Home", icon="🏠")

    # with col2:
    #   st.page_link("pages/0_XOR_Cipher.py", label="XOR Cipher", icon="1️⃣")
    
    # with col3:
    #   st.page_link("pages/1_Caesar_Cipher.py", label="Caesar Cipher", icon="2️⃣")

    # with col4:
    #   st.page_link("pages/2_Primitive_Root.py", label="Primitive Root", icon="2️⃣")

    # with col5:
    #   st.page_link("pages/3_Block_Cipher.py", label="Block Cipher", icon="2️⃣")
    # st.page_link("pages/page_2.py", label="Page 2", icon="2️⃣", disabled=True)
    # st.page_link("http://www.google.com", label="Google", icon="🌎")
