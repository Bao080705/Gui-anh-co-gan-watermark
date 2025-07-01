from Crypto.PublicKey import RSA
import os

# Tạo thư mục lưu khóa nếu chưa có
os.makedirs("rsa_keys", exist_ok=True)

# Sinh cặp khóa RSA 2048-bit
key = RSA.generate(2048)

# Lưu private key
with open("rsa_keys/private.pem", "wb") as priv_file:
    priv_file.write(key.export_key())

# Lưu public key
with open("rsa_keys/public.pem", "wb") as pub_file:
    pub_file.write(key.publickey().export_key())

print("✅ Đã tạo xong cặp khóa RSA (2048-bit) trong thư mục rsa_keys/")
