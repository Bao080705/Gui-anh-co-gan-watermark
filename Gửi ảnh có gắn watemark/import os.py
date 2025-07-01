import os

print("📂 Danh sách file hiện có:")
for f in os.listdir():
    print("-", repr(f))  # dùng repr để hiện dấu cách hoặc ký tự ẩn
