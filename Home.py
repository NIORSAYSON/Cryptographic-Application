import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)

st.set_page_config(
    page_title="Applied Cryptography Project",
    page_icon="🔑",
)

st.markdown("<h1 style='text-align: center;'>Applied Cryptography</h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Compilation of Learning Tasks</h2>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Here's where all my applied cryptography learning tasks come together. From mastering XOR Cipher and Caesar Cipher to exploring Primitive Root and Block Cipher, this compilation reflects my journey through these cryptographic techniques. Each task has been a stepping stone, enhancing my understanding and skill in securing information and communication.</p>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

st.text("Name:          Sayson, Nestor Jr. B.")
st.text("Section:       BSCS 3B")
st.text("Instructor:    Mr. Allan Ibo Jr.")
st.divider()