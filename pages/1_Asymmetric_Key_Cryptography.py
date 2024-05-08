import streamlit as st

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
    
    # Choose e such that e and t are coprime
    e = 2
    while gcd(e, t) != 1:
        e += 1
    
    # Calculate d, the multiplicative inverse of e modulo t
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
    st.sidebar.header("RSA Encryption & Decryption")
    
    p = int(st.sidebar.text_input("Value of Prime number p", 43))
    q = int(st.sidebar.text_input("Value of Prime number q", 41))
    message = st.sidebar.text_input("Message", "Hello, World!")
    
    if st.sidebar.button("Generate New Key Pairs"):
        public_key, private_key = generate_keypair(p, q)
        st.sidebar.write("Public Key: e =", public_key[0], "| n =", public_key[1])
        st.sidebar.write("Private Key: d =", private_key[0], "| n =", private_key[1])
    
    st.header("Encryption")
    st.write("Public key:", public_key[0], "| n =", public_key[1])
    if st.button("Encrypt"):
        encrypted_message = encrypt(public_key, message)
        st.write("Encrypted Message:", encrypted_message)
    
    st.header("Decryption")
    st.write("Private key:", private_key[0], "| n =", private_key[1])
    if st.button("Decrypt"):
        decrypted_message = decrypt(private_key, encrypted_message)
        st.write("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
