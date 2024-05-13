import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)

st.set_page_config(
    page_title="Applied Cryptography Project",
    page_icon="🔑",
)

st.markdown("<h1 style='text-align: center;'>Applied Cryptography - CSAC 329</h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Cryptographic Application</h2>", unsafe_allow_html=True)
st.markdown("<h5 style='text-align: center;'>GROUP 12</h5>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>The Applied Cryptography Application project aims to build a user-friendly platform that uses various cryptographic techniques to keep communication and data exchange secure. Cryptography is all about encoding and decoding messages to keep information safe and trustworthy. Our app will be a one-stop solution for anyone needing reliable encryption, decryption, and hashing features to protect their data.</p>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

st.text("Member 1:          Sayson, Nestor Jr. B.")
st.text("Member 2:          Mirandilla, Johnlery E.")
st.text("Member 3:          Demanarig, Ma. Elena C.")
st.text("Section:           BSCS 3B")
st.text("Instructor:        Mr. Allan Ibo Jr.")
st.divider()