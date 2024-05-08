import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)

st.set_page_config(
    page_title="Applied Cryptography Project",
    page_icon="🔑",
)

def home():
    st.markdown("<h1 style='text-align: center;'>Applied Cryptography</h1>", unsafe_allow_html=True)
    st.markdown("<h2 style='text-align: center;'>Compilation of Learning Tasks</h2>", unsafe_allow_html=True)
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Here's where all my applied cryptography learning tasks come together. From mastering XOR Cipher and Caesar Cipher to exploring Primitive Root and Block Cipher, this compilation reflects my journey through these cryptographic techniques. Each task has been a stepping stone, enhancing my understanding and skill in securing information and communication.</p>", unsafe_allow_html=True)
    st.markdown("<hr>", unsafe_allow_html=True)

    st.text("Name:          Sayson, Nestor Jr. B.")
    st.text("Section:       BSCS 3B")
    st.text("Instructor:    Mr. Allan Ibo Jr.")
    st.divider()



def XOR_Cipher():
      st.header('XOR Cipher', divider='rainbow')

      def xor_encrypt(plaintext, key):
          """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""

          ciphertext = bytearray()
          for i in range(len(plaintext)):
              plaintext_byte = plaintext[i]
              key_byte = key[i % len(key)]
              cipher_byte = plaintext_byte ^ key_byte
              ciphertext.append(cipher_byte)            
              st.write(f"Plaintext byte: {bin(plaintext_byte)[2:]:>08} = {chr(plaintext_byte)}")
              st.write(f"Key byte:       {bin(key_byte)[2:]:>08} = {chr(key_byte)}")
              st.write(f"XOR result:     {bin(cipher_byte)[2:]:>08} = {chr(cipher_byte)}")
              st.write("--------------------")
              
              
          return ciphertext

      def xor_decrypt(ciphertext, key):
          
          """Decrypts ciphertext using XOR cipher with the given key."""
          return xor_encrypt(ciphertext, key)   # XOR decryption is the same as encryption

      # Example usage:
      plaintext = bytes(st.text_input('Plaintext').encode())
      key = bytes(st.text_input('Key').encode())
      if st.button("Submit", key="clk_btn"):
          col1, col2 = st.columns(2)
          if not plaintext.strip() and not key.strip():
              st.error("Please input a plaintext and key.")
          elif not plaintext.strip():
              st.error("Please input a plaintext.")
          elif not key.strip():
              st.error("Please input a key.")
          elif len(plaintext) >= len(key):
              if plaintext != key:
                  try:
          
                      with col1:
                          cipher = xor_encrypt(plaintext, key)
                          st.write(f"Ciphertext:", "".join([f"{chr(byte_val)}" for byte_val in cipher]))
                      with col2:
                          decrypt = xor_decrypt(cipher, key)
                          st.write(f"Decrypted:", "".join([f"{chr(byte_va)}" for byte_va in decrypt]))
                  except:
                          st.error("Invalid Key!")
              else:
                  st.error("Plaintext should not be equal to the key")
          else:
              st.error("Plaintext length should be equal or greater than the length of key")  
      

def Caesar_Cipher():
    st.header('Caesar Cipher', divider='rainbow')
    def encrypt_decrypt(text, shift_keys, ifdecrypt):
        """
        Encrypts a text using Caesar Cipher with a list of shift keys.
        Args:
            text: The text to encrypt.
            shift_keys: A list of integers representing the shift values for each character.
            ifdecrypt: flag if decrypt or encrypt
        Returns:
            A string containing the encrypted text if encrypt and plain text if decrypt
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
        
    # Example usage
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
                  st.error("Please input a shift keys.")
              elif not all(isinstance(key, int) for key in shift_keys):
                  st.error("Please enter an integer in shift keys")
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
              st.error("Shift Keys should be an integer!")

def Primitive_Root():      
    st.header('Primitive Root', divider='rainbow') 
    
    def prime_check(q):
        int_q = int(q)   
        
        if int_q <= 1:
            return False
        for i in range(2, int(int_q**0.5)+1):
            if (int_q % i) == 0:
                return False
        return True

    def power_mod(base, exp, mod):
        res = 1 
        base %= mod
        while exp > 0:
            if exp % 2 == 1:
                res = (res * base) % mod
            exp //= 2
            base = (base * base) % mod
        return res
        
    def find_primitive_roots(q):
        int_q = int(q)  
        primitive_roots = []
        for g in range(1, int_q):
            is_primitive = True
            powers = set()
            for i in range(1, int_q):
                power = power_mod(g, i, int_q)
                powers.add(power)
                if power == 1:
                    break
            if len(powers) == int_q - 1:
                primitive_roots.append(g)
        return primitive_roots
            
    def print_primitive(p, q):
        if st.button("Submit", key="clk_btn2"):
            try:
                if not p.strip() and not q.strip():
                    st.error("Please input a Value of Prime number p and Value of Prime number q.")
                elif not p.strip():
                    st.error("Please input a Value of Prime number p.")
                elif not q.strip():
                    st.error("Please input a Value of Prime number q.")
                else:
                    int_q = int(q)  
                    int_p = int(p)
                    if not prime_check(int_p):
                        st.write(f"{int_p} is not a prime number!!")
                        return
                    
                    print_res = []
                    for g in range(1, int_p):
                        output = []
                        for j in range(1, int_p):
                            result = power_mod(g, j, int_p)
                            output.append(f"{g}^{j} mod {int_p} = {result}")
                            if result == 1:
                                break
                        if g in find_primitive_roots(int_p):
                            output[-1] += f" ==> {g} is primitive root of {int_p}|"
                        else:
                            output[-1] += "|\n"
                        print_res.append("|".join(output))
                    st.write("\n".join(print_res))
                    primitive_root = find_primitive_roots(int_p)
                    if primitive_root:
                        if int_q in primitive_root:
                            st.write(f"{int_q} is primitive root: True {primitive_root}")
                        else:
                            st.write(f"{int_q} is NOT primitive root of {int_p} - List of Primitive roots: {primitive_root}")
                    else:
                        st.write(f"{int_q} is NOT primitive root of {int_p} - List of Primitive roots: {primitive_root}")
            except:
                st.error("Inputs should be an integer!")
        
    q = st.text_input("Value of Prime number p")
    g = st.text_input("Value of Prime number q")
    print_primitive(q, g)


def Block_Cipher():
    st.header('Block Cipher', divider='rainbow') 
    def pad(data, block_size):    # CMS (Cryptographic Message Syntax). This pads with the same value as the number of padding bytes.
        # Calculate the number of bytes needed to reach a multiple of block size.
        padding_length = block_size - len(data) % block_size  
        
        # Create the padding by repeating the padding length byte.
        padding = bytes([padding_length] * padding_length)  
        
        # Add the padding to the original data.
        return data + padding                     


    def unpad(data):
        # Extract the padding length from the last byte of the data
                                        # The last byte of the data indicates the length of the padding
        # Remove the padding by slicing the data, excluding the last 'padding_length' bytes
        # This effectively removes the padding from the data
        padding_length = data[-1]
        return data[:-padding_length]                            # Return the data without the padding


    def xor_encrypt_block(plaintext_block, key):
        # Initialize an empty bytes object to store the encrypted block
        encrypted_block = b''
        # Iterate through each byte in the plaintext block
        for i in range(len(plaintext_block)):
            # XOR each byte of the plaintext block with the corresponding byte of the key
            # Use modulus operator to ensure that key bytes are reused if the key length is shorter than the plaintext block length
            encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
            
        # Return the encrypted block
        return encrypted_block                   


    def xor_decrypt_block(ciphertext_block, key):
        return xor_encrypt_block(ciphertext_block, key)  # XOR decryption is same as encryption

    def xor_encrypt(plaintext, key, block_size):
        # Initialize an empty bytes object to store the encrypted data
        encrypted_data = b''
        
        # Pad the plaintext to ensure its length is a multiple of the block size
        padded_plaintext = pad(plaintext, block_size)
        
        # Iterate through the plaintext in blocks of size block_size
        st.write("Encrypted blocks")
        for i in range(0, len(padded_plaintext), block_size):
            # Extract a block of plaintext
            plaintext_block = padded_plaintext[i:i+block_size]
            # Encrypt the plaintext block using XOR with the key
            st.write(f"Plain  block[{i // block_size}]: {plaintext_block.hex()} : {plaintext_block}")
            encrypted_block = xor_encrypt_block(plaintext_block, key)
            # Append the encrypted block to the encrypted data
            encrypted_data += encrypted_block
        # Return the encrypted data
            st.write(f"Cipher block[{i // block_size}]: {encrypted_block.hex()} : {encrypted_block}")
        return encrypted_data                               


    def xor_decrypt(ciphertext, key, block_size):
        # Initialize an empty bytes object to store the decrypted data
        decrypted_data = b''
        
        # Iterate through the ciphertext in blocks of size block_size
        st.write("\nDecrypted blocks")
            
        for i in range(0, len(ciphertext), block_size):
            # Extract the current block of ciphertext
            ciphertext_block = ciphertext[i:i+block_size]
            
            # Decrypt the current block using xor_decrypt_block function
            decrypted_block = xor_decrypt_block(ciphertext_block, key)
            
            # Append the decrypted block to the decrypted data
            decrypted_data += decrypted_block
            st.write(f"block[{i // block_size}]: {decrypted_block.hex()}: {decrypted_block}")
        # Remove any padding from the decrypted data
        unpadded_decrypted_data = unpad(decrypted_data)
        
        # Return the unpadded decrypted data
        return unpadded_decrypted_data                               



    # Define the plaintext and encryption key
    plain_text = bytes(st.text_area('Plain text').encode())
    key_byte = bytes(st.text_input('Key Byte').encode())
    block_size = st.text_input("Block Size")
    
    # Define the block size for encryption (adjust according to your needs)
    if st.button("Submit", key="clk_btn3"):
        if not plain_text.strip() and not key_byte.strip() and not block_size.strip():
            st.error("Please input a Plain text, Key, and Block Size.")
        elif not plain_text.strip() and not key_byte.strip():
            st.error("Please input a Plain text and Key.")
        elif not plain_text.strip() and not block_size.strip():
            st.error("Please input a Plain text and Block Size.")
        elif not key_byte.strip() and not block_size.strip():
            st.error("Please input a Key and Block Size.")
        elif not plain_text.strip():
            st.error("Please input a Plain text.")
        elif not key_byte.strip():
            st.error("Please input a Key.")
        elif not block_size.strip():
            st.error("Please input a Block Size.")
        else:
            int_block_size = int(block_size)
            if int_block_size not in [8, 16, 32, 64, 128]:
                st.write('Block size must be one of 8, 16,  32, 64, or  128 bytes')
            else:
                key_byte = pad(key_byte, int_block_size)   # Pad the key

                # Encryption
                encrypted_data = xor_encrypt(plain_text, key_byte, int_block_size)
                decrypted_data = xor_decrypt(encrypted_data, key_byte, int_block_size)
                
                # Decryption


                st.write("\nOriginal plaintext:", plain_text)
                st.write("Key byte      :", key_byte)
                st.write("Key hex       :", key_byte.hex())
                st.write("Encrypted data:", encrypted_data.hex())  # st.write encrypted data in hexadecimal format
                st.write("Decrypted data:", decrypted_data.hex())
                st.write("Decrypted data:", decrypted_data)



# st.write(b'Hello Bob, this '.hex())




          


if __name__ == "__main__":
    # add_selectbox = st.sidebar.selectbox(
    #     "Types Of Cryptography",
    #     ("Symmetric Key Cryptography", "Asymmetric Key Cryptography", "Hash Functions")
    # )

    tab1, tab2, tab3, tab4 = st.tabs(["Home", "XOR Cipher", "Caesar Cipher", "Block Cipher"])

    with tab1:
        home()

    with tab2:
        XOR_Cipher()
    
    with tab3:
        Caesar_Cipher()

    # with tab4:
    #     Primitive_Root()
    
    with tab4:
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
