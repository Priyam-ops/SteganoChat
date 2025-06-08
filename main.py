import tkinter as tk
from tkinter import scrolledtext, messagebox
from steg import hide_message, reveal_message
import requests
from PIL import Image
from io import BytesIO
import os
import socket
import threading

RANDOM_IMAGE_PATH = "random_image.png"

def download_random_image(path=RANDOM_IMAGE_PATH, size=(400, 400)):
    url = f"https://picsum.photos/{size[0]}/{size[1]}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        img = Image.open(BytesIO(response.content))
        img.save(path)
        return path
    except Exception as e:
        messagebox.showerror("Error", f"Failed to download random image: {e}")
        return None

class ChatStegGUI:
    def __init__(self, master, my_name="Me", peer_name="Peer", send_ip='localhost', send_port=5001, listen_port=5001):
        self.master = master
        self.my_name = my_name
        self.peer_name = peer_name
        self.send_ip = send_ip
        self.send_port = send_port
        self.listen_port = listen_port

        master.title(f"SteganoChat - {self.my_name}")

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(master, state='disabled', width=60, height=20, font=("Arial", 12))
        self.chat_display.pack(side=tk.TOP, padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Bottom frame for entry and send button
        bottom_frame = tk.Frame(master)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 10))

        # Message entry
        self.message_entry = tk.Entry(bottom_frame, width=50, font=("Arial", 12))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        self.message_entry.focus_set()  # Set focus here

        # Send button
        self.send_btn = tk.Button(bottom_frame, text="Send", width=10, command=self.send_message, font=("Arial", 12, "bold"))
        self.send_btn.pack(side=tk.LEFT, padx=(10, 0))

        # Start receiver thread
        threading.Thread(target=self.receive_image, daemon=True).start()

    def append_chat(self, sender, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"{sender}: {message}\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def send_message(self):
        message = self.message_entry.get().strip()
        if not message:
            self.message_entry.focus_set()
            return
        self.append_chat(self.my_name, message)
        self.message_entry.delete(0, tk.END)
        self.message_entry.focus_set()  # Return focus after sending

        # Hide message in image
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

        # Send image via socket
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
                # Reveal message
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
   
    gui = ChatStegGUI(root, my_name="Me", peer_name="Peer", send_ip='localhost', send_port=5001, listen_port=5001)
    root.mainloop()