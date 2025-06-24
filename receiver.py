# Import thư viện socket để tạo kết nối mạng
import socket
# Import thư viện json để mã hóa/giải mã dữ liệu JSON
import json
# Import thư viện base64 để mã hóa/giải mã dữ liệu nhị phân thành chuỗi
import base64
# Import tkinter để tạo giao diện người dùng (GUI)
import tkinter as tk
# Import ttk và scrolledtext từ tkinter để tạo các widget giao diện nâng cao (tab, text box cuộn)
from tkinter import ttk, scrolledtext
# Import DES và PKCS1_OAEP từ Crypto để mã hóa/giải mã DES và RSA
from Crypto.Cipher import DES, PKCS1_OAEP
# Import RSA từ Crypto để xử lý khóa công khai/riêng tư RSA
from Crypto.PublicKey import RSA
# Import pkcs1_15 từ Crypto để ký số và xác minh chữ ký
from Crypto.Signature import pkcs1_15
# Import SHA256 từ Crypto để tạo hash SHA-256
from Crypto.Hash import SHA256
# Import threading để chạy socket trong luồng riêng, không chặn GUI
import threading

# Hàm unpad: Loại bỏ padding khỏi dữ liệu giải mã DES
def unpad(text):
    # Lấy độ dài padding từ byte cuối cùng
    padding_length = text[-1]
    # Trả về dữ liệu đã bỏ padding (cắt bỏ các byte cuối)
    return text[:-padding_length]

# Hàm decrypt_des_key: Giải mã khóa DES bằng khóa riêng RSA
def decrypt_des_key(receiver_private_key, encrypted_des_key):
    # Tạo đối tượng cipher RSA với khóa riêng và thuật toán SHA256
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key, hashAlgo=SHA256)
    # Giải mã khóa DES đã được mã hóa
    des_key = cipher_rsa.decrypt(encrypted_des_key)
    # Trả về khóa DES đã giải mã
    return des_key

# Hàm decrypt_message: Giải mã tin nhắn bằng khóa DES
def decrypt_message(des_key, ciphertext):
    # Tách vector khởi tạo (IV) từ 8 byte đầu của ciphertext
    iv = ciphertext[:8]
    # Tạo đối tượng cipher DES với khóa DES, chế độ CFB, và IV
    cipher_des = DES.new(des_key, DES.MODE_CFB, iv=iv)
    # Giải mã ciphertext (bỏ IV) và loại bỏ padding
    decrypted_message = unpad(cipher_des.decrypt(ciphertext[8:]))
    # Chuyển dữ liệu giải mã từ bytes sang chuỗi
    return decrypted_message.decode()

# Hàm verify_signature: Xác minh chữ ký số
def verify_signature(public_key, signature, ciphertext):
    # Tạo hash SHA-256 của ciphertext
    hash_obj = SHA256.new(ciphertext)
    try:
        # Xác minh chữ ký với khóa công khai và hash
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        # Nếu thành công, trả về True
        return True
    except:
        # Nếu thất bại, trả về False
        return False

# Hàm calculate_hash: Tính hash SHA-256 của dữ liệu
def calculate_hash(ciphertext):
    # Tạo hash SHA-256 và trả về dưới dạng chuỗi hex
    return SHA256.new(ciphertext).hexdigest()

# Lớp ReceiverApp: Ứng dụng GUI cho phía nhận tin (Receiver)
class ReceiverApp:
    # Hàm khởi tạo
    def __init__(self, root):
        # Lưu đối tượng cửa sổ chính
        self.root = root
        # Đặt tiêu đề cửa sổ
        self.root.title("Agent Hằng - Sinh")
        # Đặt kích thước cửa sổ (700x600)
        self.root.geometry("700x600")
        # Đặt màu nền tối (dark theme)
        self.root.configure(bg="#1C2526")

        # Khởi tạo các biến toàn cục
        self.server = None  # Socket server
        self.conn = None  # Kết nối với Sender
        self.receiver_private_key = None  # Khóa riêng RSA của Receiver
        self.receiver_public_key = None  # Khóa công khai RSA của Receiver
        self.sender_public_key = None  # Khóa công khai RSA của Sender

        # Cấu hình style cho giao diện
        style = ttk.Style()
        # Sử dụng theme "clam" cho giao diện hiện đại
        style.theme_use("clam")
        # Cấu hình màu nền và chữ cho notebook (tab)
        style.configure("TNotebook", background="#1C2526", foreground="#FFFFFF")
        # Cấu hình tab: màu nền, chữ, padding
        style.configure("TNotebook.Tab", background="#2E2E2E", foreground="#00FF99", padding=[10, 5])
        # Hiệu ứng khi chọn/hover tab
        style.map("TNotebook.Tab", background=[("selected", "#00FF99"), ("active", "#3A3A3A")], foreground=[("selected", "#1C2526")])

        # Tạo frame cho header
        header_frame = tk.Frame(root, bg="#1C2526")
        # Đặt frame trải rộng theo chiều ngang
        header_frame.pack(fill="x", pady=10)
        # Tạo label tiêu đề "SecureCom" với font lớn, màu xanh neon
        tk.Label(header_frame, text="SecureCom", font=("Arial", 20, "bold"), fg="#00FF99", bg="#1C2526").pack()
        # Tạo label phụ "Receiving Station" với font nhỏ
        tk.Label(header_frame, text="Receiving Station", font=("Arial", 12), fg="#FFFFFF", bg="#1C2526").pack()

        # Tạo frame cho log (khu vực hiển thị thông tin)
        log_frame = tk.Frame(root, bg="#1C2526")
        # Đặt frame mở rộng toàn bộ không gian
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Tạo notebook (tabbed interface)
        self.notebook = ttk.Notebook(log_frame)
        # Đặt notebook mở rộng toàn bộ frame
        self.notebook.pack(fill="both", expand=True)

        # Tạo text box cuộn cho tab Handshake
        self.handshake_log = scrolledtext.ScrolledText(self.notebook, width=80, height=20, state='disabled', font=("Courier New", 10), bg="#2E2E2E", fg="#FFFFFF")
        # Tạo text box cuộn cho tab Decryption
        self.encryption_log = scrolledtext.ScrolledText(self.notebook, width=80, height=20, state='disabled', font=("Courier New", 10), bg="#2E2E2E", fg="#FFFFFF")
        # Tạo text box cuộn cho tab Verification
        self.verification_log = scrolledtext.ScrolledText(self.notebook, width=80, height=20, state='disabled', font=("Courier New", 10), bg="#2E2E2E", fg="#FFFFFF")
        # Tạo text box cuộn cho tab Status
        self.status_log = scrolledtext.ScrolledText(self.notebook, width=80, height=20, state='disabled', font=("Courier New", 10), bg="#2E2E2E", fg="#FFFFFF")

        # Thêm các text box vào notebook với tên tab tương ứng
        self.notebook.add(self.handshake_log, text="Handshake")
        self.notebook.add(self.encryption_log, text="Decryption")
        self.notebook.add(self.verification_log, text="Verification")
        self.notebook.add(self.status_log, text="Status")

        # Tải khóa RSA của Receiver
        try:
            # Đọc khóa riêng từ file
            self.receiver_private_key = RSA.import_key(open("receiver_private.pem").read())
            # Đọc khóa công khai từ file
            self.receiver_public_key = RSA.import_key(open("receiver_public.pem").read())
            # Ghi log thành công
            self.log_status("Loaded receiver's RSA keys successfully.")
        except FileNotFoundError:
            # Ghi log lỗi nếu file không tồn tại
            self.log_status("Error: PEM files not found.")
            self.log_status("Please run generate_keys.py first.")

        # Chạy server trong luồng riêng
        threading.Thread(target=self.start_server, daemon=True).start()

    # Hàm ghi log vào tab Handshake
    def log_handshake(self, message):
        self.log(self.handshake_log, message)

    # Hàm ghi log vào tab Decryption
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

    # Hàm chạy server socket
    def start_server(self):
        # Tạo socket TCP
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Bind socket vào localhost, cổng 9999
            self.server.bind(('localhost', 9999))
            # Lắng nghe tối đa 1 kết nối
            self.server.listen(1)
            # Ghi log trạng thái
            self.log_status("Receiver listening on port 9999...")
        except OSError:
            # Ghi log lỗi nếu cổng bị chiếm
            self.log_status("Error: Port 9999 is in use or cannot be bound.")
            return

        # Chấp nhận kết nối từ Sender
        self.conn, addr = self.server.accept()
        # Ghi log thông tin kết nối (IP, port)
        self.log_status(f"Connected by {addr}")

        try:
            # Nhận greeting từ Sender
            data = self.conn.recv(1024).decode()
            # Ghi log greeting nhận được
            self.log_handshake(f"Received agent code: {data}")

            # Kiểm tra greeting có đúng "Hello!"
            if data != "Hello!":
                # Ghi log lỗi handshake
                self.log_handshake("Handshake failed!")
                self.log_handshake(f"Expected 'Hello!', received '{data}'.")
                # Gửi phản hồi NACK
                self.conn.send("NACK: Invalid greeting".encode())
                # Đóng kết nối
                self.conn.close()
                return

            # Ghi log handshake thành công
            self.log_handshake("Received correct 'Hello!' greeting.")
            # Gửi phản hồi "Ready!"
            self.log_handshake("Sending response: Ready!")
            self.conn.send("Ready!".encode())

            # Gửi khóa công khai của Receiver
            self.log_handshake("Sending receiver's public key.")
            self.conn.send(self.receiver_public_key.export_key())
        except UnicodeDecodeError:
            # Ghi log lỗi nếu dữ liệu không hợp lệ
            self.log_handshake("Handshake failed!")
            self.log_handshake("Invalid data received.")
            # Gửi phản hồi NACK
            self.conn.send("NACK: Invalid data".encode())
            # Đóng kết nối
            self.conn.close()
            return

        try:
            # Nhận khóa công khai của Sender
            sender_public_key_pem = self.conn.recv(4096)
            # Import khóa công khai
            self.sender_public_key = RSA.import_key(sender_public_key_pem)
            # Ghi log thành công
            self.log_handshake("Received sender's public key.")
        except ValueError as e:
            # Ghi log lỗi nếu khóa không hợp lệ
            self.log_handshake("Error: Invalid sender public key format.")
            self.log_handshake(f"Details: {e}")
            # Gửi phản hồi NACK
            self.conn.send("NACK: Invalid sender public key".encode())
            # Đóng kết nối
            self.conn.close()
            return

        try:
            # Nhận dữ liệu xác thực (chữ ký, khóa DES mã hóa)
            auth_data = json.loads(self.conn.recv(4096).decode())
            # Giải mã chữ ký từ Base64
            signature = base64.b64decode(auth_data["signed_info"])
            # Giải mã khóa DES từ Base64
            encrypted_des_key = base64.b64decode(auth_data["encrypted_des_key"])
            # Ghi log nhận dữ liệu xác thực
            self.log_verification("Received authentication data.")
            # Ghi log khóa DES mã hóa
            self.log_encryption(f"Encrypted DES key (Base64): {auth_data['encrypted_des_key']}")
        except (json.JSONDecodeError, KeyError):
            # Ghi log lỗi nếu dữ liệu JSON không hợp lệ
            self.log_verification("Error: Invalid authentication data.")
            # Gửi phản hồi NACK
            self.conn.send("NACK: Invalid auth data".encode())
            # Đóng kết nối
            self.conn.close()
            return

        # ID của Sender để xác minh
        sender_id = "123456"
        # Ghi log bắt đầu xác minh ID
        self.log_verification(f"Verifying sender ID: {sender_id}")
        # Tạo hash của sender_id
        hash_obj = SHA256.new(sender_id.encode())
        # Xác minh chữ ký của sender_id
        if not verify_signature(self.sender_public_key, signature, sender_id.encode()):
            # Ghi log lỗi nếu chữ ký không hợp lệ
            self.log_verification("Signature verification failed!")
            # Gửi phản hồi NACK
            self.conn.send("NACK: Invalid signature".encode())
            # Đóng kết nối
            self.conn.close()
            return
        # Ghi log xác minh thành công
        self.log_verification("Sender ID signature verified successfully.")

        try:
            # Giải mã khóa DES
            des_key = decrypt_des_key(self.receiver_private_key, encrypted_des_key)
            # Ghi log thành công
            self.log_encryption("Decrypted DES key successfully.")
        except ValueError:
            # Ghi log lỗi nếu giải mã thất bại
            self.log_encryption("Error: Failed to decrypt DES key.")
            # Gửi phản hồi NACK
            self.conn.send("NACK: DES key decryption failed".encode())
            # Đóng kết nối
            self.conn.close()
            return

        try:
            # Nhận dữ liệu tin nhắn (ciphertext, hash, chữ ký)
            message_data = json.loads(self.conn.recv(4096).decode())
            # Giải mã ciphertext từ Base64
            ciphertext = base64.b64decode(message_data["cipher"])
            # Lấy hash nhận được
            received_hash = message_data["hash"]
            # Giải mã chữ ký từ Base64
            signature = base64.b64decode(message_data["sig"])
            # Ghi log nhận dữ liệu tin nhắn
            self.log_encryption("Received encrypted message data.")
            # Ghi log ciphertext
            self.log_encryption(f"Ciphertext (Base64): {message_data['cipher']}")
            # Ghi log hash nhận được
            self.log_verification(f"Received SHA-256 hash: {received_hash}")
        except (json.JSONDecodeError, KeyError):
            # Ghi log lỗi nếu dữ liệu JSON không hợp lệ
            self.log_encryption("Error: Invalid message data.")
            # Gửi phản hồi NACK
            self.conn.send("NACK: Invalid message data".encode())
            # Đóng kết nối
            self.conn.close()
            return

        # Tính hash của ciphertext (bỏ IV)
        calculated_hash = calculate_hash(ciphertext[8:])
        # Ghi log hash tính toán
        self.log_verification(f"Calculated SHA-256 hash: {calculated_hash}")
        # Ghi log so sánh hash
        self.log_verification(f"Comparing hashes: Received = {received_hash}, Calculated = {calculated_hash}")
        # Kiểm tra hash có khớp
        if calculated_hash != received_hash:
            # Ghi log lỗi nếu hash không khớp
            self.log_verification("Hash mismatch!")
            # Gửi phản hồi NACK
            self.conn.send("NACK: Hash mismatch".encode())
            # Đóng kết nối
            self.conn.close()
            return
        # Ghi log hash khớp
        self.log_verification("Hash verification passed.")

        # Xác minh chữ ký của ciphertext
        self.log_verification("Verifying signature of ciphertext hash.")
        if not verify_signature(self.sender_public_key, signature, ciphertext[8:]):
            # Ghi log lỗi nếu chữ ký không hợp lệ
            self.log_verification("Signature verification failed!")
            # Gửi phản hồi NACK
            self.conn.send("NACK: Invalid signature".encode())
            # Đóng kết nối
            self.conn.close()
            return
        # Ghi log xác minh thành công
        self.log_verification("Ciphertext signature verified successfully.")

        try:
            # Giải mã tin nhắn
            message = decrypt_message(des_key, ciphertext)
            # Ghi log tin nhắn giải mã
            self.log_encryption(f"Decrypted message: {message}")
        except ValueError:
            # Ghi log lỗi nếu giải mã thất bại
            self.log_encryption("Error: Failed to decrypt message.")
            # Gửi phản hồi NACK
            self.conn.send("NACK: Decryption failed".encode())
            # Đóng kết nối
            self.conn.close()
            return

        # Ghi log gửi phản hồi ACK
        self.log_status("Sending ACK response.")
        # Gửi phản hồi ACK
        self.conn.send("ACK".encode())

        # Đóng kết nối client
        self.conn.close()
        # Đóng server
        self.server.close()
        # Ghi log trạng thái
        self.log_status("Connection closed.")

# Chạy ứng dụng nếu file được chạy trực tiếp
if __name__ == "__main__":
    # Tạo cửa sổ Tkinter
    root = tk.Tk()
    # Tạo đối tượng ReceiverApp
    app = ReceiverApp(root)
    # Chạy vòng lặp chính của GUI
    root.mainloop()