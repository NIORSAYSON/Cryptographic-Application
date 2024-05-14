import streamlit as st
import hashlib
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)

st.set_page_config(
    page_title="Hashing Functions",
    page_icon="🔑",
)

# Functions to hash text using md5, sha1, sha256, and sh512
def hash_md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def hash_sha1(text):
    return hashlib.sha1(text.encode()).hexdigest()

def hash_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

def hash_sha512(text):
    return hashlib.sha512(text.encode()).hexdigest()

# Functions to hash file contents using md5, sha1, sha256, and sh512
def hash_file_md5(file_contents):
    return hashlib.md5(file_contents.encode()).hexdigest()

def hash_file_sha1(file_contents):
    return hashlib.sha1(file_contents.encode()).hexdigest()

def hash_file_sha256(file_contents):
    return hashlib.sha256(file_contents.encode()).hexdigest()

def hash_file_sha512(file_contents):
    return hashlib.sha512(file_contents.encode()).hexdigest()

def main():
    # Create tabs for each hashing function
    tabs = st.tabs(["MD5", "SHA-1", "SHA-256", "SHA-512"])
    
    for i, option in enumerate(["MD5", "SHA-1", "SHA-256", "SHA-512"]):
        with tabs[i]:
            st.header(f'{option} Hash Generator', divider='rainbow')
            # Radio button to choose between text input and file upload
            input_type = st.radio(f"Choose input type for {option}:", ("Text", "File"))
            
            if input_type == "Text":
                # input function for text 
                input_text = st.text_area(f"Enter text for {option}:")
                
                if st.button(f"Hash Text using {option}"):
                    # Perform hashing based on the selected algorithm
                    if option == "MD5":
                        hashed_text = hash_md5(input_text)
                    elif option == "SHA-1":
                        hashed_text = hash_sha1(input_text)
                    elif option == "SHA-256":
                        hashed_text = hash_sha256(input_text)
                    elif option == "SHA-512":
                        hashed_text = hash_sha512(input_text)
                    
                    # Display the hashed text
                    st.write(f"Hashed Text ({option}):")
                    st.code(hashed_text)
                
            elif input_type == "File":
                # input function for file
                uploaded_file = st.file_uploader(f"Upload a file for {option}")
                if uploaded_file is not None:
                    # Read the contents of the file and decode it to a string
                    file_contents = uploaded_file.getvalue().decode("utf-8")
                    if st.button(f"Hash File using {option}"):
                        # Perform hashing based on the selected function
                        if option == "MD5":
                            hashed_text = hash_file_md5(file_contents)
                        elif option == "SHA-1":
                            hashed_text = hash_file_sha1(file_contents)
                        elif option == "SHA-256":
                            hashed_text = hash_file_sha256(file_contents)
                        elif option == "SHA-512":
                            hashed_text = hash_file_sha512(file_contents)
                        
                        # Display the hashed file contents
                        st.write(f"Hashed File ({option}):")
                        st.write(hashed_text)

if __name__ == "__main__":
    main()
