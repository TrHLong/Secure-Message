# Import thư viện socket để tạo kết nối mạng
import socket
# Import thư viện json để mã hóa/giải mã dữ liệu JSON
import json
# Import thư viện base64 để mã hóa/giải mã dữ liệu nhị phân thành chuỗi
import base64
# Import tkinter để tạo giao diện người dùng (GUI)
import tkinter as tk
# Import ttk và scrolledtext từ tkinter để tạo các widget giao diện nâng cao
from tkinter import ttk, scrolledtext
# Import DES và PKCS1_OAEP từ Crypto để mã hóa/giải mã DES và RSA
from Crypto.Cipher import DES, PKCS1_OAEP
# Import RSA từ Crypto để xử lý khóa công khai/riêng tư RSA
from Crypto.PublicKey import RSA
# Import pkcs1_15 từ Crypto để ký số và xác minh chữ ký
from Crypto.Signature import pkcs1_15
# Import SHA256 từ Crypto để tạo hash SHA-256
from Crypto.Hash import SHA256
# Import get_random_bytes từ Crypto để tạo dữ liệu ngẫu nhiên
from Crypto.Random import get_random_bytes
# Import threading để chạy socket trong luồng riêng, không chặn GUI
import threading

# Hàm pad: Thêm padding cho dữ liệu trước khi mã hóa DES
def pad(text):
    # Tính độ dài padding cần thêm để chia hết cho 8
    padding_length = 8 - (len(text) % 8)
    # Tạo padding bằng cách lặp lại byte độ dài padding
    padding = bytes([padding_length]) * padding_length
    # Thêm padding vào dữ liệu
    return text + padding

# Hàm sign_message: Ký số thông điệp bằng khóa riêng RSA
def sign_message(private_key, message):
    # Tạo hash SHA-256 của thông điệp
    hash_obj = SHA256.new(message.encode())
    # Ký hash bằng khóa riêng
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    # Trả về chữ ký
    return signature

# Hàm encrypt_des_key: Mã hóa khóa DES bằng khóa công khai RSA
def encrypt_des_key(receiver_public_key, des_key):
    # Tạo đối tượng cipher RSA với khóa công khai và thuật toán SHA256
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key, hashAlgo=SHA256)
    # Mã hóa khóa DES
    encrypted_des_key = cipher_rsa.encrypt(des_key)
    # Trả về khóa DES đã mã hóa
    return encrypted_des_key

# Hàm encrypt_message: Mã hóa tin nhắn bằng khóa DES
def encrypt_message(des_key, message):
    # Tạo vector khởi tạo (IV) ngẫu nhiên 8 byte
    iv = get_random_bytes(8)
    # Tạo đối tượng cipher DES với khóa DES, chế độ CFB, và IV
    cipher_des = DES.new(des_key, DES.MODE_CFB, iv=iv)
    # Mã hóa tin nhắn đã được padding
    ciphertext = cipher_des.encrypt(pad(message.encode()))
    # Trả về IV nối với ciphertext
    return iv + ciphertext

# Hàm calculate_hash: Tính hash SHA-256 của dữ liệu
def calculate_hash(ciphertext):
    # Tạo hash SHA-256 và trả về dưới dạng chuỗi hex
    return SHA256.new(ciphertext).hexdigest()

# Lớp SenderApp: Ứng dụng GUI cho phía gửi tin (Sender)
class SenderApp:
    # Hàm khởi tạo
    def __init__(self, root):
        # Lưu đối tượng cửa sổ chính
        self.root = root
        # Đặt tiêu đề cửa sổ
        self.root.title("Director of the LHS : Long")
        # Đặt kích thước cửa sổ (700x600)
        self.root.geometry("700x600")
        # Đặt màu nền tối (dark theme)
        self.root.configure(bg="#1C2526")

        # Khởi tạo các biến toàn cục
        self.client = None  # Socket client
        self.sender_private_key = None  # Khóa riêng RSA của Sender
        self.sender_public_key = None  # Khóa công khai RSA của Sender
        self.receiver_public_key = None  # Khóa công khai RSA của Receiver
        self.des_key = None  # Khóa DES ngẫu nhiên

        # Cấu hình style cho giao diện
        style = ttk.Style()
        # Sử dụng theme "clam" cho giao diện hiện đại
        style.theme_use("clam")
        # Cấu hình màu nền và chữ cho notebook
        style.configure("TNotebook", background="#1C2526", foreground="#FFFFFF")
        # Cấu hình tab: màu nền, chữ, padding
        style.configure("TNotebook.Tab", background="#2E2E2E", foreground="#00FF99", padding=[10, 5])
        # Hiệu ứng khi chọn/hover tab
        style.map("TNotebook.Tab", background=[("selected", "#00FF99"), ("active", "#3A3A3A")], foreground=[("selected", "#1C2526")])
        # Cấu hình nút: màu nền, chữ
        style.configure("TButton", background="#2E2E2E", foreground="#FFFFFF", font=("Arial", 10))
        # Hiệu ứng hover cho nút
        style.map("TButton", background=[("active", "#00FF99")], foreground=[("active", "#1C2526")])

        # Tạo frame cho header
        header_frame = tk.Frame(root, bg="#1C2526")
        # Đặt frame trải rộng theo chiều ngang
        header_frame.pack(fill="x", pady=10)
        # Tạo label tiêu đề "SecureCom" với font lớn, màu xanh neon
        tk.Label(header_frame, text="SecureCom", font=("Arial", 20, "bold"), fg="#00FF99", bg="#1C2526").pack()
        # Tạo label phụ "Classified Messaging System" với font nhỏ
        tk.Label(header_frame, text="Classified Messaging System", font=("Arial", 12), fg="#FFFFFF", bg="#1C2526").pack()

        # Tạo frame cho input
        input_frame = tk.Frame(root, bg="#1C2526")
        # Đặt frame với padding
        input_frame.pack(pady=10)

        # Tạo label "Agent Code"
        tk.Label(input_frame, text="Agent Code:", font=("Arial", 10), fg="#FFFFFF", bg="#1C2526").grid(row=0, column=0, padx=5, sticky="e")
        # Tạo ô nhập Agent Code, mặc định "Hello!"
        self.greeting_entry = tk.Entry(input_frame, width=40, font=("Arial", 10), bg="#2E2E2E", fg="#FFFFFF", insertbackground="#FFFFFF")
        self.greeting_entry.insert(0, "Hello!")
        self.greeting_entry.grid(row=0, column=1, padx=5)

        # Tạo nút "Initiate Protocol" để bắt đầu handshake
        ttk.Button(input_frame, text="Initiate Protocol", command=self.start_handshake).grid(row=0, column=2, padx=5)

        # Tạo label "Secret Message"
        tk.Label(input_frame, text="Secret Message:", font=("Arial", 10), fg="#FFFFFF", bg="#1C2526").grid(row=1, column=0, padx=5, sticky="e")
        # Tạo ô nhập tin nhắn bí mật
        self.message_entry = tk.Entry(input_frame, width=40, font=("Arial", 10), bg="#2E2E2E", fg="#FFFFFF", insertbackground="#FFFFFF")
        self.message_entry.grid(row=1, column=1, padx=5)

        # Tạo nút "Transmit Message" để gửi tin nhắn
        ttk.Button(input_frame, text="Transmit Message", command=self.send_message).grid(row=1, column=2, padx=5)

        # Tạo frame cho log
        log_frame = tk.Frame(root, bg="#1C2526")
        # Đặt frame mở rộng toàn bộ không gian
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Tạo notebook (tabbed interface)
        self.notebook = ttk.Notebook(log_frame)
        # Đặt notebook mở rộng toàn bộ frame
        self.notebook.pack(fill="both", expand=True)

        # Tạo text box cuộn cho tab Handshake
        self.handshake_log = scrolledtext.ScrolledText(self.notebook, width=80, height=15, state='disabled', font=("Courier New", 10), bg="#2E2E2E", fg="#FFFFFF")
        # Tạo text box cuộn cho tab Encryption
        self.encryption_log = scrolledtext.ScrolledText(self.notebook, width=80, height=15, state='disabled', font=("Courier New", 10), bg="#2E2E2E", fg="#FFFFFF")
        # Tạo text box cuộn cho tab Verification
        self.verification_log = scrolledtext.ScrolledText(self.notebook, width=80, height=15, state='disabled', font=("Courier New", 10), bg="#2E2E2E", fg="#FFFFFF")
        # Tạo text box cuộn cho tab Status
        self.status_log = scrolledtext.ScrolledText(self.notebook, width=80, height=15, state='disabled', font=("Courier New", 10), bg="#2E2E2E", fg="#FFFFFF")

        # Thêm các text box vào notebook với tên tab tương ứng
        self.notebook.add(self.handshake_log, text="Handshake")
        self.notebook.add(self.encryption_log, text="Encryption")
        self.notebook.add(self.verification_log, text="Verification")
        self.notebook.add(self.status_log, text="Status")

        # Tải khóa RSA của Sender
        try:
            # Đọc khóa riêng từ file
            self.sender_private_key = RSA.import_key(open("sender_private.pem").read())
            # Đọc khóa công khai từ file
            self.sender_public_key = RSA.import_key(open("sender_public.pem").read())
            # Ghi log thành công
            self.log_status("Loaded sender's RSA keys successfully.")
        except FileNotFoundError:
            # Ghi log lỗi nếu file không tồn tại
            self.log_status("Error: PEM files not found.")
            self.log_status("Please run generate_keys.py first.")

    # Hàm ghi log vào tab Handshake
    def log_handshake(self, message):
        self.log(self.handshake_log, message)

    # Hàm ghi log vào tab Encryption
    def log_encryption(self, message):
        self.log(self.encryption_log, message)

    # Hàm ghi log vào tab Verification
    def log_verification(self, message):
        self.log(self.verification_log, message)

    # Hàm ghi log vào tab Status
    def log_status(self, message):
        self.log(self.status_log, message)

    # Hàm ghi log chung cho các tab
    def log(self, text_widget, message):
        # Bật chế độ chỉnh sửa text box
        text_widget.config(state='normal')
        # Thêm message vào cuối text box, cách dòng
        text_widget.insert(tk.END, message + "\n\n")
        # Tắt chế độ chỉnh sửa
        text_widget.config(state='disabled')
        # Cuộn đến cuối để hiển thị log mới
        text_widget.see(tk.END)

    # Hàm bắt đầu handshake
    def start_handshake(self):
        # Chạy handshake trong luồng riêng
        threading.Thread(target=self._handshake_thread, daemon=True).start()

    # Hàm thực hiện handshake
    def _handshake_thread(self):
        # Tạo socket TCP
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Kết nối tới Receiver tại localhost:9999
            self.client.connect(('localhost', 9999))
            # Ghi log thành công
            self.log_status("Connected to receiver at localhost:9999.")
        except ConnectionRefusedError:
            # Ghi log lỗi nếu kết nối thất bại
            self.log_status("Error: Could not connect to receiver.")
            self.log_status("Ensure receiver.py is running.")
            return

        # Lấy greeting từ ô nhập
        greeting = self.greeting_entry.get()
        # Ghi log greeting gửi đi
        self.log_handshake(f"Sending agent code: {greeting}")
        # Gửi greeting
        self.client.send(greeting.encode())

        # Nhận phản hồi từ Receiver
        response = self.client.recv(1024).decode()
        # Ghi log phản hồi
        self.log_handshake(f"Received response: {response}")

        # Kiểm tra phản hồi có đúng "Ready!"
        if response != "Ready!":
            # Ghi log lỗi handshake
            self.log_handshake("Handshake failed!")
            self.log_handshake("Receiver did not respond with 'Ready!'.")
            # Đóng kết nối
            self.client.close()
            # Ghi log trạng thái
            self.log_status("Connection closed.")
            return

        # Nhận khóa công khai của Receiver
        receiver_public_key_pem = self.client.recv(4096)
        try:
            # Import khóa công khai
            self.receiver_public_key = RSA.import_key(receiver_public_key_pem)
            # Ghi log handshake thành công
            self.log_handshake("Handshake successful!")
            self.log_handshake("Received receiver's public key.")
        except ValueError as e:
            # Ghi log lỗi nếu khóa không hợp lệ
            self.log_handshake("Error: Invalid receiver public key format.")
            self.log_handshake(f"Details: {e}")
            # Đóng kết nối
            self.client.close()
            # Ghi log trạng thái
            self.log_status("Connection closed.")
            return

        # Gửi khóa công khai của Sender
        self.client.send(self.sender_public_key.export_key())
        # Ghi log gửi khóa
        self.log_handshake("Sent sender's public key to receiver.")

        # Tạo khóa DES ngẫu nhiên
        self.des_key = get_random_bytes(8)
        # Ghi log tạo khóa
        self.log_encryption("Generated random DES key.")

    # Hàm gửi tin nhắn
    def send_message(self):
        # Kiểm tra handshake đã hoàn tất
        if not self.client or not self.receiver_public_key or not self.des_key:
            # Ghi log lỗi nếu chưa handshake
            self.log_status("Error: Handshake not completed.")
            return
        # Chạy gửi tin nhắn trong luồng riêng
        threading.Thread(target=self._send_message_thread, daemon=True).start()

    # Hàm thực hiện gửi tin nhắn
    def _send_message_thread(self):
        # ID của Sender để xác thực
        sender_id = "123456"
        # Ghi log bắt đầu xác thực
        self.log_verification(f"Preparing to authenticate with ID: {sender_id}")
        # Ký số sender_id
        signature = sign_message(self.sender_private_key, sender_id)
        # Mã hóa chữ ký thành Base64
        signature_b64 = base64.b64encode(signature).decode()
        # Ghi log ký số
        self.log_verification("Signed sender ID with RSA private key.")

        # Mã hóa khóa DES bằng khóa công khai của Receiver
        encrypted_des_key = encrypt_des_key(self.receiver_public_key, self.des_key)
        # Mã hóa khóa DES thành Base64
        encrypted_des_key_b64 = base64.b64encode(encrypted_des_key).decode()
        # Ghi log khóa DES mã hóa
        self.log_encryption(f"Encrypted DES key (Base64): {encrypted_des_key_b64}")

        # Tạo dữ liệu xác thực
        auth_data = {
            "signed_info": signature_b64,
            "encrypted_des_key": encrypted_des_key_b64
        }
        # Ghi log gửi dữ liệu xác thực
        self.log_verification("Sending authentication data.")
        # Gửi dữ liệu xác thực dưới dạng JSON
        self.client.send(json.dumps(auth_data).encode())

        # Lấy tin nhắn từ ô nhập
        text = self.message_entry.get()
        # Ghi log tin nhắn gốc
        self.log_encryption(f"Original message: {text}")
        # Mã hóa tin nhắn bằng DES
        ciphertext = encrypt_message(self.des_key, text)
        # Mã hóa ciphertext thành Base64
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        # Ghi log ciphertext
        self.log_encryption(f"Encrypted message (ciphertext, Base64): {ciphertext_b64}")

        # Tính hash của ciphertext (bỏ IV)
        ciphertext_hash = calculate_hash(ciphertext[8:])
        # Ghi log hash
        self.log_verification(f"SHA-256 hash of ciphertext: {ciphertext_hash}")

        # Tạo hash của ciphertext để ký
        hash_obj = SHA256.new(ciphertext[8:])
        # Ký hash bằng khóa riêng
        signed_hash = pkcs1_15.new(self.sender_private_key).sign(hash_obj)
        # Mã hóa chữ ký thành Base64
        signed_hash_b64 = base64.b64encode(signed_hash).decode()
        # Ghi log ký hash
        self.log_verification("Signed hash of ciphertext with RSA private key.")

        # Tạo dữ liệu tin nhắn
        message_data = {
            "cipher": ciphertext_b64,
            "hash": ciphertext_hash,
            "sig": signed_hash_b64
        }
        # Ghi log gửi dữ liệu tin nhắn
        self.log_encryption("Sending encrypted message data.")
        # Gửi dữ liệu tin nhắn dưới dạng JSON
        self.client.send(json.dumps(message_data).encode())

        # Nhận phản hồi từ Receiver
        response = self.client.recv(1024).decode()
        # Ghi log phản hồi
        self.log_status(f"Receiver response: {response}")

        # Đóng kết nối
        self.client.close()
        # Ghi log trạng thái
        self.log_status("Connection closed.")

# Chạy ứng dụng nếu file được chạy trực tiếp
if __name__ == "__main__":
    # Tạo cửa sổ Tkinter
    root = tk.Tk()
    # Tạo đối tượng SenderApp
    app = SenderApp(root)
    # Chạy vòng lặp chính của GUI
    root.mainloop()