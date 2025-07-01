import socket, json, base64
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Util.Padding import unpad

def main():
    # 1. Load khóa RSA (public để kiểm tra chữ ký, private để giải RSA)
    public_key = RSA.import_key(open("rsa_keys/public.pem", "rb").read())
    private_key = RSA.import_key(open("rsa_keys/private.pem", "rb").read())

    # 2. Mở socket
    with socket.socket() as s:
        s.bind(("localhost", 9999))
        s.listen(1)
        print("📥 Receiver đang đợi kết nối...")
        conn, addr = s.accept()
        with conn:
            print("📡 Đã kết nối từ", addr)
            if conn.recv(1024) == b"Hello!":
                conn.sendall(b"Ready!")
                data = conn.recv(1000000)
                packet = json.loads(data)

                # 3. Decode các thành phần
                iv = base64.b64decode(packet["iv"])
                ciphertext = base64.b64decode(packet["cipher"])
                signature = base64.b64decode(packet["sig"])
                enc_key = base64.b64decode(packet["enc_key"])
                metadata = packet["metadata"]
                recv_hash = packet["hash"]

                # 4. Tính lại hash
                hash_check = SHA512.new(iv + ciphertext).hexdigest()

                # 5. Giải mã DES key
                cipher_rsa = PKCS1_v1_5.new(private_key)
                session_key = cipher_rsa.decrypt(enc_key, b"ERROR")

                # 6. Xác thực chữ ký
                try:
                    pkcs1_15.new(public_key).verify(SHA512.new(metadata.encode()), signature)
                except (ValueError, TypeError):
                    conn.sendall(b"NACK - Invalid Signature")
                    return

                # 7. So sánh hash
                if hash_check != recv_hash:
                    conn.sendall(b"NACK - Integrity Error")
                    return

                # 8. Giải mã ảnh
                des_cipher = DES.new(session_key, DES.MODE_CBC, iv)
                img_data = unpad(des_cipher.decrypt(ciphertext), 8)
                with open("received_photo.jpg", "wb") as f:
                    f.write(img_data)

                print("✅ Ảnh đã được giải mã và lưu lại.")
                conn.sendall(b"ACK")

if __name__ == "__main__":
    main()
