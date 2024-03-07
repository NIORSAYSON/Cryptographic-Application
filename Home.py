import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)

st.set_page_config(
    page_title="Applied Cryptography Project",
    page_icon="🔑",
)

  
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
          if len(plaintext) >= len(key):
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

if __name__ == "__main__":
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Home", "XOR Cipher", "Caesar Cipher", "Primitive Root", "Block Cipher"])

    with tab1:
      st.page_link("Home.py", label="Home")

    with tab2:
      XOR_Cipher()
    
    with tab3:
      st.image("https://static.streamlit.io/examples/cat.jpg", width=200)

    with tab4:
      st.image("https://static.streamlit.io/examples/cat.jpg", width=200)
    
    with tab5:
      st.image("https://static.streamlit.io/examples/cat.jpg", width=200)
      
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
