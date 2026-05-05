import io

import streamlit as st
from PIL import Image

from steganography_web.steganography import (
    decode_image,
    encode_image,
    get_capacity_chars,
)

st.set_page_config(page_title="Steganography App", page_icon="🔐", layout="centered")

st.title("🔐 Steganography Web App")
st.write("Hide a secret message inside an image using LSB steganography and password-based encryption.")

tab1, tab2 = st.tabs(["Encode Message", "Decode Message"])


with tab1:
    st.subheader("Encode a Message into an Image")

    uploaded_image = st.file_uploader(
        "Upload an image",
        type=["png", "bmp", "jpg", "jpeg"],
        key="encode_uploader"
    )

    secret_message = st.text_area("Secret message", height=150)
    encode_password = st.text_input("Password", type="password", key="encode_password")

    if uploaded_image is not None:
        image = Image.open(uploaded_image)
        st.image(image, caption="Original image", use_container_width=True)

        capacity = get_capacity_chars(image)
        st.info(f"Estimated capacity: about {capacity} characters (rough estimate). Best results with PNG.")

        if st.button("Encode Image"):
            if not secret_message.strip():
                st.error("Please enter a secret message.")
            elif not encode_password.strip():
                st.error("Please enter a password.")
            else:
                try:
                    encoded_image = encode_image(image, secret_message, encode_password)

                    output = io.BytesIO()
                    encoded_image.save(output, format="PNG")
                    output.seek(0)

                    st.success("Message encoded successfully.")
                    st.download_button(
                        label="Download encoded image",
                        data=output,
                        file_name="encoded_image.png",
                        mime="image/png"
                    )
                except ValueError as e:
                    st.error(f"Input error: {e}")
                except Exception:
                    st.error("Unexpected error occurred.")


with tab2:
    st.subheader("Decode a Message from an Image")

    decode_uploaded_image = st.file_uploader(
        "Upload an encoded image",
        type=["png", "bmp", "jpg", "jpeg"],
        key="decode_uploader"
    )

    decode_password = st.text_input("Password", type="password", key="decode_password")

    if decode_uploaded_image is not None:
        image = Image.open(decode_uploaded_image)
        st.image(image, caption="Encoded image", use_container_width=True)

        if st.button("Decode Message"):
            if not decode_password.strip():
                st.error("Please enter the password.")
            else:
                try:
                    decoded_message = decode_image(image, decode_password)
                    st.success("Message decoded successfully.")
                    st.text_area("Decoded message", decoded_message, height=150)
                except ValueError as e:
                    st.error(f"Input error: {e}")
                except Exception:
                    st.error("Unexpected error occurred.")


st.markdown("---")
st.caption("Tip: Use PNG for the encoded image. JPEG compression can damage hidden data.")
