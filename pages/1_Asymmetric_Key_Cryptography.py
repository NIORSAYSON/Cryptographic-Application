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
    
    p = 43
    q = 41
    n = p * q
    t = (p - 1) * (q - 1)
    
    public_key, private_key = generate_keypair(p, q)
    
    st.header("RSA Encryption")
    st.write("Public key: e =", public_key[0], "| n =", public_key[1])
    st.write("Deryption Private key: d =", private_key[0], "| n =", private_key[1])
    
    message = st.text_area("Message:", "Hello Bob! How are you?")
    st.write("message:", [ord(char) for char in message])
    
    if st.button("Encrypt"):
        encrypted_message = encrypt(public_key, message)
        st.write("Cipher text:", encrypted_message)
        st.write("Cipher text:", ''.join([chr(char) for char in encrypted_message]))
    
    st.header("RSA Decryption")
    st.write("To Decrypt, use private key", private_key[0], "| n =", private_key[1])
    st.write("Key:", private_key[0])
    st.write("n:", private_key[1])
    if st.button("Decrypt"):
        decrypted_message = decrypt(private_key, encrypted_message)
        st.write("Plain text:", decrypted_message)

if __name__ == "__main__":
    main()
