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
                    output[-1] += "|"
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
        
        
    q = st.text_input("Q")
    g = st.text_input("G")
    
    print_primitive(q, g)

         

          


if __name__ == "__main__":
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Home", "XOR Cipher", "Caesar Cipher", "Primitive Root", "Block Cipher"])

    with tab1:
      st.page_link("Home.py", label="Home")

    with tab2:
      XOR_Cipher()
    
    with tab3:
      Caesar_Cipher()

    with tab4:
      Primitive_Root()
    
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
