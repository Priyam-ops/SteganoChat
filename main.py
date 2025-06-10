import tkinter as tk
from tkinter import scrolledtext
from steg import hide_message, reveal_message
import requests
from PIL import Image, ImageTk
from io import BytesIO
import os
import socket
import threading

RANDOM_IMAGE_PATH = "random_image.png"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def download_random_image(path=RANDOM_IMAGE_PATH, size=(400, 400)):
    url = f"https://picsum.photos/{size[0]}/{size[1]}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        img = Image.open(BytesIO(response.content))
        img.save(path)
        return path
    except Exception as e:
        return None

class RoundedEntry(tk.Canvas):
    def __init__(self, parent, radius=10, **kwargs):
        width = kwargs.pop('width', 200)
        height = kwargs.pop('height', 36)
        font = kwargs.pop('font', ("Segoe UI", 11))
        tk.Canvas.__init__(self, parent, highlightthickness=0, bg="#ece5dd")
        self.radius = radius
        self.entry = tk.Entry(self, bd=0, relief=tk.FLAT, font=font, fg="#222", bg="white", insertbackground="#222")
        self.create_rounded_rect(0, 0, width, height, radius, fill="white", outline="#cccccc")
        self.update_idletasks()
        entry_req_height = self.entry.winfo_reqheight()
        y_offset = (height - entry_req_height) // 2
        self.create_window(
            (radius, y_offset),
            window=self.entry,
            anchor="nw",
            width=width - 2 * radius
        )
        self.configure(width=width, height=height, bg="#ece5dd")

    def create_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1+r, y1,
            x2-r, y1,
            x2, y1,
            x2, y1+r,
            x2, y2-r,
            x2, y2,
            x2-r, y2,
            x1+r, y2,
            x1, y2,
            x1, y2-r,
            x1, y1+r,
            x1, y1
        ]
        return self.create_polygon(points, smooth=True, **kwargs)

    def get(self):
        return self.entry.get()

    def insert(self, index, string): # type: ignore
        return self.entry.insert(index, string)

    def delete(self, first, last=None): # type: ignore
        return self.entry.delete(first, last)

    def entry_delete(self, first, last=None):
        return self.entry.delete(first, last)

    def bind(self, sequence=None, func=None, add=None): # type: ignore
        tk.Canvas.bind(self, sequence, func, add)
        self.entry.bind(sequence, func, add)

    def focus_set(self):
        self.entry.focus_set()

class ChatStegGUI:
    def __init__(self, master, my_name="Me", peer_name="Peer", send_ip='localhost', send_port=5001, listen_port=5001):
        self.master = master
        self.my_name = my_name
        self.peer_name = peer_name
        self.send_ip = send_ip
        self.send_port = send_port
        self.listen_port = listen_port

        master.title(f"SteganoChat - {self.my_name} ({self.send_ip})")
        master.geometry("700x600")
        master.configure(bg="#ece5dd")  # WhatsApp background color

        # === Set background image on Canvas ===
        try:
            self.bg_image = Image.open("background.png")
            self.bg_image = self.bg_image.resize((700, 600), Image.Resampling.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(self.bg_image)
        except Exception as e:
            print(f"Background image error: {e}")
            self.bg_photo = None

        self.canvas = tk.Canvas(master, width=700, height=600, highlightthickness=0, bg="#ece5dd")
        self.canvas.pack(fill="both", expand=True)
        if self.bg_photo:
            self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")

        # Header bar
        self.header = tk.Frame(self.canvas, bg="#075e54", height=60)
        self.header_window = self.canvas.create_window(0, 0, anchor="nw", window=self.header, width=700, height=60)
        self.header_label = tk.Label(self.header, text="SteganoChat", font=("Segoe UI", 16, "bold"), fg="white", bg="#075e54")
        self.header_label.pack(side=tk.LEFT, padx=20, pady=10)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(
            self.canvas, state='disabled', width=60, height=18,
            font=("Segoe UI", 12), fg="#222", bg="#f7f7f7", insertbackground="#222", borderwidth=0, highlightthickness=0
        )
        chat_display_window = self.canvas.create_window(
            20, 70, anchor="nw", window=self.chat_display, width=660, height=370
        )

        # Bottom input area
        self.input_frame = tk.Frame(self.canvas, bg="#ece5dd")
        self.input_window = self.canvas.create_window(
            0, 540, anchor="nw", window=self.input_frame, width=700, height=60
        )

        # Receiver IP entry (rounded)
        self.receiver_ip_entry = RoundedEntry(self.input_frame, width=180, height=36, font=("Segoe UI", 11))
        self.receiver_ip_entry.insert(0, "Receiver IP (e.g. 192.168.1.XX)")
        self.receiver_ip_entry.pack(side=tk.LEFT, padx=(10, 5), pady=12)
        self.receiver_ip_entry.bind("<FocusIn>", lambda event: self._clear_placeholder())

        # Message entry (rounded)
        self.message_entry = RoundedEntry(self.input_frame, width=340, height=36, font=("Segoe UI", 11))
        self.message_entry.pack(side=tk.LEFT, padx=(5, 5), pady=12, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        self.message_entry.focus_set()

        # Send button (rounded, WhatsApp style)
        try:
            send_img = Image.open("send_icon.png")
            send_img = send_img.resize((36, 36), Image.Resampling.LANCZOS)
            self.send_icon = ImageTk.PhotoImage(send_img)
            self.send_btn = tk.Button(self.input_frame, image=self.send_icon, command=self.send_message, bd=0, bg="#25d366", activebackground="#25d366", relief=tk.FLAT)
        except Exception:
            self.send_btn = tk.Button(self.input_frame, text="Send", width=6, command=self.send_message, font=("Segoe UI", 11, "bold"), bg="#25d366", fg="white", activebackground="#25d366", relief=tk.FLAT)
        self.send_btn.pack(side=tk.LEFT, padx=(5, 10), pady=12)

        # Start receiver thread
        threading.Thread(target=self.receive_image, daemon=True).start()

    def _clear_placeholder(self):
        if self.receiver_ip_entry.get() == "Receiver IP (e.g. 192.168.1.XX)":
            self.receiver_ip_entry.entry_delete(0, tk.END)

    def append_chat(self, sender, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"{sender}: {message}\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def send_message(self):
        message = self.message_entry.get().strip()
        receiver_ip = self.receiver_ip_entry.get().strip()
        if not message:
            self.message_entry.focus_set()
            return
        if not receiver_ip or receiver_ip == "Receiver IP (e.g. 192.168.1.XX)":
            self.append_chat("System", "Please enter the receiver's IP address.")
            self.receiver_ip_entry.focus_set()
            return
        self.send_ip = receiver_ip

        self.append_chat(self.my_name, message)
        self.message_entry.entry_delete(0, tk.END)
        self.message_entry.focus_set()

        img_path = download_random_image()
        if not img_path:
            self.append_chat("System", "Failed to get image for steganography.")
            return
        output_path = "to_send.png"
        try:
            hide_message(img_path, message, output_path)
        except Exception as e:
            self.append_chat("System", f"Failed to hide message: {e}")
            return

        try:
            s = socket.socket()
            s.connect((self.send_ip, self.send_port))
            with open(output_path, 'rb') as f:
                data = f.read()
                s.sendall(len(data).to_bytes(8, 'big') + data)
            s.close()
        except Exception as e:
            self.append_chat("System", f"Failed to send message: {e}")

    def receive_image(self):
        while True:
            try:
                s = socket.socket()
                s.bind(('0.0.0.0', self.listen_port))
                s.listen(1)
                conn, addr = s.accept()
                length = int.from_bytes(conn.recv(8), 'big')
                data = b''
                while len(data) < length:
                    packet = conn.recv(4096)
                    if not packet:
                        break
                    data += packet
                with open("received.png", 'wb') as f:
                    f.write(data)
                conn.close()
                s.close()
                try:
                    message = reveal_message("received.png")
                    if message:
                        self.append_chat(self.peer_name, message)
                    else:
                        self.append_chat(self.peer_name, "[Received an image, but no hidden message found!]")
                except Exception as e:
                    self.append_chat("System", f"Failed to reveal message: {e}")
                finally:
                    try:
                        os.remove("received.png")
                    except Exception as e:
                        self.append_chat("System", f"Failed to delete received image: {e}")
            except Exception as e:
                self.append_chat("System", f"Receiver error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    local_ip = get_local_ip()
    gui = ChatStegGUI(
        root,
        my_name="Me",
        peer_name="Peer",
        send_ip=local_ip,
        send_port=5001,
        listen_port=5001
    )
    root.mainloop()