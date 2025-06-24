from Crypto.PublicKey import RSA  # Nhập mô-đun RSA từ thư viện pycryptodome để làm việc với các khóa RSA

# Function to generate and save RSA keys
def generate_keys(key_name):
    # Tạo một cặp khóa RSA mới với độ dài khóa 2048 bit
    key = RSA.generate(2048)
    
    # Xuất khóa riêng tư dưới dạng PEM (Private Key)
    private_key = key.export_key()
    
    # Xuất khóa công khai dưới dạng PEM (Public Key)
    public_key = key.publickey().export_key()
    
    # Save keys to files - Lưu khóa vào các file với tên đã cho
    with open(f"{key_name}_private.pem", "wb") as f:
        f.write(private_key)  # Ghi khóa riêng tư vào file

    with open(f"{key_name}_public.pem", "wb") as f:
        f.write(public_key)  # Ghi khóa công khai vào file

    # In ra thông báo xác nhận rằng các khóa đã được tạo và lưu thành công
    print(f"{key_name} keys have been generated and saved.")

# Generate RSA keys for Sender and Receiver
generate_keys("sender")  # Tạo và lưu cặp khóa cho người gửi (sender)
generate_keys("receiver")  # Tạo và lưu cặp khóa cho người nhận (receiver)
