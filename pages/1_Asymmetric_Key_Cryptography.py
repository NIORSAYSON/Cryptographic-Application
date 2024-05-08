import streamlit as st

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def encrypt(message, e, n):
    cipher = [pow(ord(char), e, n) for char in message]
    return cipher

def decrypt(cipher, d, n):
    message = ''.join([chr(pow(char, d, n)) for char in cipher])
    return message

def main():
    st.title("RSA Encryption and Decryption")
    st.write("Enter your message below:")

    message = st.text_area("Message")

    p = 43
    q = 41
    n = p * q
    t = (p - 1) * (q - 1)

    e = 1129
    d = mod_inverse(e, t)

    if st.button("Encrypt"):
        if message:
            encrypted_message = encrypt(message, e, n)
            st.write("Encrypted Message:", encrypted_message)
        else:
            st.error("Please enter a message to encrypt.")

    if st.button("Decrypt"):
        cipher_text = st.text_area("Cipher Text")
        if cipher_text:
            try:
                cipher = [int(char) for char in cipher_text.split(',')]
                decrypted_message = decrypt(cipher, d, n)
                st.write("Decrypted Message:", decrypted_message)
            except ValueError:
                st.error("Invalid cipher text format. Please enter comma-separated integers.")
        else:
            st.error("Please enter the cipher text to decrypt.")

if __name__ == "__main__":
    main()
