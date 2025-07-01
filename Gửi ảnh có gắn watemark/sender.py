import socket, json, base64, time
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from PIL import Image, ImageDraw, ImageFont

def add_watermark(input_path, output_path, text):
    image = Image.open(input_path).convert("RGBA")
    watermark = Image.new("RGBA", image.size)
    draw = ImageDraw.Draw(watermark)

    try:
        font = ImageFont.truetype("arial.ttf", size=int(image.size[1] / 10))
    except:
        font = ImageFont.load_default()

    # ✅ Tính kích thước bằng textbbox (chuẩn mới)
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    # Vị trí: góc dưới bên phải
    position = (image.size[0] - text_width - 30, image.size[1] - text_height - 30)

    draw.text(position, text, font=font, fill=(255, 255, 255, 200))

    combined = Image.alpha_composite(image, watermark)
    combined.convert("RGB").save(output_path, "JPEG")

def main():
    # 1. Watermark
    add_watermark("photo.jpg", "photo_watermarked.jpg", "© by NHOM 6")

    # 2. Load RSA keys
    public_key = RSA.import_key(open("rsa_keys/public.pem", "rb").read())
    private_key = RSA.import_key(open("rsa_keys/private.pem", "rb").read())

    # 3. DES key & IV
    session_key = get_random_bytes(8)
    iv = get_random_bytes(8)

    # 4. Metadata + Signature
    metadata = f"photo.jpg|{int(time.time())}|© by NHOM 6"
    h = SHA512.new(metadata.encode())
    signature = pkcs1_15.new(private_key).sign(h)

    # 5. Mã hóa DES key bằng RSA
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_key = cipher_rsa.encrypt(session_key)

    # 6. Mã hóa ảnh bằng DES
    with open("photo_watermarked.jpg", "rb") as f:
        img_data = f.read()
    cipher = DES.new(session_key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(img_data, 8))

    # 7. Tính SHA-512(IV + ciphertext)
    hashval = SHA512.new(iv + ciphertext).hexdigest()

    # 8. Gửi
    payload = {
        "iv": base64.b64encode(iv).decode(),
        "cipher": base64.b64encode(ciphertext).decode(),
        "hash": hashval,
        "sig": base64.b64encode(signature).decode(),
        "enc_key": base64.b64encode(encrypted_key).decode(),
        "metadata": metadata
    }

    with socket.socket() as s:
        s.connect(("localhost", 9999))
        s.sendall(b"Hello!")
        if s.recv(1024) == b"Ready!":
            s.sendall(json.dumps(payload).encode())
            response = s.recv(1024).decode()
            print("Receiver response:", response)

if __name__ == "__main__":
    main()
