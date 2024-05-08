import streamlit as st
import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, t):
    d = 0
    x1, x2 = 0, 1
    y1, y2 = 1, 0
    temp_t = t
    
    while e > 0:
        temp1 = temp_t // e
        temp2 = temp_t - temp1 * e
        temp_t = e
        e = temp2
        
        x = x2 - temp1 * x1
        y = y2 - temp1 * y1
        
        x2 = x1
        x1 = x
        y2 = y1
        y1 = y
    
    if temp_t == 1:
        d = y2 + t
    return d

def generate_keypair(p, q):
    n = p * q
    t = (p - 1) * (q - 1)
    
    possible_e_values = [i for i in range(2, t) if gcd(i, t) == 1]
    e = random.choice(possible_e_values)
    
    d = multiplicative_inverse(e, t)
    
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

def decrypt(private_key, ciphertext):
    d, n = private_key
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)

def main():
    st.title("Asymmetric Key Cryptography (RSA)")
    
    p = int(st.text_input("Value of Prime number p:", 43))
    q = int(st.text_input("Value of Prime number q:", 41))
    
    if st.button("Generate New Key Pairs"):
        public_key, private_key = generate_keypair(p, q)
        st.sidebar.write("Public Key: e =", public_key[0], "| n =", public_key[1])
        st.sidebar.write("Private Key: d =", private_key[0], "| n =", private_key[1])
    
    message = st.text_area("Message:", "Hello Bob! How are you?")
    
    if st.button("Encrypt"):
        encrypted_message = encrypt(public_key, message)
        st.write("Cipher text:", encrypted_message)
        st.write("Cipher text:", ''.join([chr(char) for char in encrypted_message]))
    
    if st.button("Decrypt"):
        decrypted_message = decrypt(private_key, encrypted_message)
        st.write("Plain text:", decrypted_message)

if __name__ == "__main__":
    main()
