import hashlib
import tkinter as tk
from tkinter import filedialog, ttk
import time

#------------------class-Password-Hash-Cracker-App------------------#

class PasswordHashCrackerApp:
    def __init__(self, root, back_callback):
        self.root = root
        self.back_callback = back_callback
        self.root.title("AstroCrypt")
        self.root.geometry("750x650")
        self.root.configure(bg="#1E1E1E")
        self.root.resizable(False, False)

        self.bg_color = "#1E1E1E"
        self.fg_color = "#FFFFFF"
        self.fg1_color = "#FF0000"
        self.entry_bg_color = "#222222"
        self.textarea_bg_color = "#333333"

        self.hash_types = [
            "MD5",
            "SHA1",
            "SHA224",
            "SHA256",
            "SHA384",
            "SHA512",
            "sha3_224()",
            "sha3_256()",
            "sha3_384()",
            "sha3_512()",
            "shake_128()",
            "shake_256()",
            "blake2b()",
            "blake2s()"
        ]

        self.create_widgets()

    def create_widgets(self):
        self.root.config(bg=self.bg_color)

        header_label = tk.Label(
            self.root, text="AstroCrypt", font=("Felix Titling", 32, "bold"), bg=self.bg_color, fg=self.fg1_color
        )
        header_label.pack(pady=20)

        hash_frame = tk.Frame(self.root, bg=self.bg_color)
        hash_frame.pack()

        hash_label = tk.Label(
            hash_frame, text="Hash Type:", font=("Times", 15, "bold"), bg=self.bg_color, fg=self.fg1_color
        )
        hash_label.grid(row=0, column=0, padx=10, pady=10, sticky="W")

        self.hash_type_combobox = ttk.Combobox(
            hash_frame, values=self.hash_types, font=("Times", 10,"bold"), state="readonly", width=7
        )
        self.hash_type_combobox.current(0)
        self.hash_type_combobox.grid(row=0, column=1, padx=10, pady=10)

        hash_entry_label = tk.Label(
            hash_frame, text="Hash:", font=("Times", 15, "bold"), bg=self.bg_color, fg=self.fg1_color
        )
        hash_entry_label.grid(row=1, column=0, padx=10, pady=10, sticky="W")

        self.hash_entry = tk.Entry(
            hash_frame, width=40, font=("Times", 15), bg=self.entry_bg_color, fg=self.fg_color
        )
        self.hash_entry.grid(row=1, column=1, padx=10, pady=10)

        file_frame = tk.Frame(self.root, bg=self.bg_color)
        file_frame.pack(pady=10)

        password_file_label = tk.Label(
            file_frame, text="Password File:", font=("Times", 15, "bold"), bg=self.bg_color, fg=self.fg1_color
        )
        password_file_label.grid(row=0, column=0, padx=10, pady=10, sticky="W")

        self.password_file_entry = tk.Entry(
            file_frame, width=30, font=("Times", 15), bg=self.entry_bg_color, fg=self.fg_color
        )
        self.password_file_entry.grid(row=0, column=1, padx=10, pady=10, sticky="W")

        browse_button = tk.Button(
            file_frame, text="Browse", command=self.browse_password_file, font=("Felix Titling", 15,"bold"), bg=self.bg_color, fg=self.fg1_color
        )
        browse_button.grid(row=0, column=2, padx=10, pady=10, sticky="W")

        log_frame = tk.Frame(self.root, bg=self.bg_color)
        log_frame.pack(pady=10)

        log_label = tk.Label(log_frame, text="Log:", font=("Times", 15,"bold"), bg=self.bg_color, fg=self.fg1_color)
        log_label.pack()

        self.log_text = tk.Text(
            log_frame, width=60, height=10, font=("Courier New", 13), bg=self.textarea_bg_color, fg=self.fg_color
        )

        self.log_text.pack()

        crack_button = tk.Button(
        self.root, text="Crack", command=self.find_password_hash, font=("Felix Titling", 15, "bold"),
        bg=self.bg_color, fg=self.fg1_color
        )
        crack_button.pack(pady=0, padx=5)

        back_button = tk.Button(
            self.root, text="Back to Options", command=self.back_to_main,
            font=("Felix Titling", 15, "bold"), bg=self.bg_color, fg=self.fg1_color
        )
        back_button.pack(pady=0, side=tk.RIGHT, padx=5)

    def back_to_main(self):
        self.root.destroy()
        main()


    def browse_password_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Password File", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if file_path:
            self.password_file_entry.delete(0, tk.END)
            self.password_file_entry.insert(tk.END, file_path)

    def find_password_hash(self):
        hash_type = self.hash_type_combobox.get()
        wanted_hash = self.hash_entry.get()
        password_file = self.password_file_entry.get()
        if not password_file:
            messagebox.showwarning("Error", "No password file selected!")
            return

        attempts = 0
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, "Attempting to crack {} hash: {}!\n".format(hash_type, wanted_hash))

        try:
            with open(password_file, "r", encoding="latin-1") as password_list:
                for password in password_list:
                    password = password.strip("\n").encode("latin-1")
                    password_hash = getattr(hashlib, hash_type.lower())(password).hexdigest()
                    self.log_text.insert(tk.END, "[{}] {} == {}\n".format(attempts, password.decode("latin-1"), password_hash))
                    self.log_text.see(tk.END)
                    self.log_text.update()

                    if password_hash == wanted_hash:
                        self.log_text.delete("1.0", tk.END)
                        self.log_text.insert(tk.END, "Password hash found after {} attempts!\n".format(attempts))
                        self.log_text.insert(tk.END, "=====================================\n")
                        self.log_text.insert(tk.END, "Cracked Password: {}\n".format(password.decode("latin-1")))
                        self.log_text.insert(tk.END, "Hash: {}\n".format(password_hash))
                        self.log_text.insert(tk.END, "=====================================\n")
                        messagebox.showinfo("Success", "Password hash found!")
                        return

                    attempts += 1

            self.log_text.insert(tk.END, "Password hash not found!\n")
            messagebox.showinfo("Failure", "Password hash not found!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

#------------------class-ASCII-Animation------------------#

class ASCIIAnimation:
    def __init__(self, root):
        self.root = root
        self.root.title("AstroCrypt")
        self.root.geometry("750x650")
        self.root.resizable(False, False)

        self.bg_color = "#1E1E1E"
        self.fg_color = "#FFFFFF"
        self.fg1_color = "#FF0000"

        self.animation_text = r"""
                                 .';cloooolc:,.                                 
                              .cx0NWMMMMMMMMWWXOo,.                             
                            'dXWMMMMMMMMMMMMMMMMMNO:.                           
                           cKMMMMMMMMMMMMMMMMMMMMMMWk'                          
                          cXMMMMMMMMMMMMMMMMMMMMMMMMW0,                         
                         ;KMMMMMMMMMMMMMMMMMMMMMMMMMMWk.                        
                        .xWMMMMMMMMMMMMMMMMMMMMMMMMMMMX:                        
                        ;KMMMMMMMMMMMMMMMMMMMMMMMMMMMMWd                        
                        lWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMx.                       
                       .dWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMk.                       
                       .xMMWMMMMMMMMMMMMMMMMMMMMMMMMWWMk.                       
                        oWOccokKWMMMMMMMMMMMMMWXkoc::kNd.                       
                        ,K0'   .;dXMMMMMMMMMWOc.    ,0K;                        
                         lXk.     .dNMMMMMMKc.     ;0No.                        
                         .oX0:.     cXMMMMK:     'dXWx.                         
                          .cXNOl,.   oNMMWo. .':xXMNd.                          
                            ;0WMNKOxdkNMMNOxkKNWMMXo.                           
                             .xNMMMMMMMMMMMMMMMMW0;                             
                               :0WMMMMMMMMMMMMMXd.                              
                                .c0WMMMMMMMMMXx,                                
                                  .;dOKXXX0xc.                                  
                                     .....                                     
        """

        self.animation_label = tk.Label(
            self.root, text="", font=("Courier New", 10), bg=self.bg_color, fg=self.fg1_color
        )
        self.animation_label.pack(pady=100)

        self.animate()
        self.stack = [self.show_options]

    def animate(self):
        for i in range(len(self.animation_text)):
            self.animation_label.config(text=self.animation_text[:i])
            self.root.update()
            time.sleep(0)  

        self.animation_label.pack_forget()  
        self.show_options()  

    def identify_hash(self, hash_value):
        hash_algorithms = [
            hashlib.md5(),
            hashlib.sha1(),
            hashlib.sha224(),
            hashlib.sha256(),
            hashlib.sha384(),
            hashlib.sha512(),
            hashlib.sha3_224(),
            hashlib.sha3_256(),
            hashlib.sha3_384(),
            hashlib.sha3_512(),
            hashlib.shake_128(),
            hashlib.shake_256(),
            hashlib.blake2b(),
            hashlib.blake2s()
        ]

        identified_hashes = []

        for hash_alg in hash_algorithms:
            if len(hash_value) == hash_alg.digest_size * 2:
                identified_hashes.append(hash_alg.name)

        return identified_hashes

    def show_options(self):
        options_frame = tk.Frame(self.root, bg="#1E1E1E")
        options_frame.pack(pady=100)

        label = tk.Label(
            options_frame, text="AstroCrypt", font=("Felix Titling", 42, "bold"), bg="#1E1E1E", fg="#FF0000"
        )
        label.pack(pady=20)

        label = tk.Label(
            options_frame, text="Choose an Option :", font=("Times", 17, "bold"), bg="#1E1E1E", fg="#FFFFFF"
        )
        label.pack(pady=30)


        def start_animation():
            options_frame.pack_forget()  
            self.animation_label.pack(pady=100)  

        def start_password_cracker():
            options_frame.pack_forget()  
            password_cracker_app = PasswordHashCrackerApp(self.root, self.show_options)

        def open_identify_hash_type():
            options_frame.pack_forget()  
            self.identify_hash_input()

        cracker_button = tk.Button(
            options_frame, text="Password Hash Cracker", command=start_password_cracker, font=("Felix Titling", 15, "bold"), bg="#1E1E1E", fg="#FF0000"
        )
        cracker_button.pack(pady=20)

        identify_button = tk.Button(
            options_frame, text="Identify Hash Type", command=open_identify_hash_type, font=("Felix Titling", 15, "bold"), bg="#1E1E1E", fg="#FF0000"
        )
        identify_button.pack(pady=20)

    def identify_hash_input(self):
        hash_input_frame = tk.Frame(self.root, bg="#1E1E1E")
        hash_input_frame.pack(pady=100)

        label = tk.Label(
            hash_input_frame, text="AstroCrypt", font=("Felix Titling", 42, "bold"), bg="#1E1E1E", fg="#FF0000"
        )
        label.pack(pady=20)

        label = tk.Label(
            hash_input_frame, text="Enter the hash value:", font=("Times", 15, "bold"), bg="#1E1E1E", fg="#FFFFFF"
        )
        label.pack(pady=10)

        hash_entry = tk.Entry(
            hash_input_frame, width=40, font=("Times", 15), bg="#222222", fg="#FFFFFF"
        )
        hash_entry.pack(pady=20)

        def identify():
            hash_value = hash_entry.get()
            if hash_value:
                identified_hashes = self.identify_hash(hash_value)
                if identified_hashes:
                    hash_types = "\n".join(identified_hashes)
                    result_text.config(state=tk.NORMAL)
                    result_text.delete("1.0", tk.END)
                    result_text.insert(tk.END, f"Identified hash type(s):\t{hash_types}")
                    result_text.config(state=tk.DISABLED)
                else:
                    result_text.config(state=tk.NORMAL)
                    result_text.delete("1.0", tk.END)
                    result_text.insert(tk.END, "Hash type not identified.")
                    result_text.config(state=tk.DISABLED)
            else:
                result_text.config(state=tk.NORMAL)
                result_text.delete("1.0", tk.END)
                result_text.insert(tk.END, "Please enter a valid hash value.")
                result_text.config(state=tk.DISABLED)

        identify_button = tk.Button(
            hash_input_frame, text="Identify", command=identify, font=("Felix Titling", 15, "bold"), bg="#1E1E1E", fg="#FFFFFF"
        )
        identify_button.pack(pady=10)

        back_button = tk.Button(
            hash_input_frame, text="Back to Options", command=self.back_to_main,
            font=("Felix Titling", 15, "bold"), bg="#1E1E1E", fg="#FF0000"
        )
        back_button.pack(pady=10)

        result_text = tk.Text(
            hash_input_frame, width=40, height=5, font=("Courier New", 12), bg="#333333", fg="#FFFFFF", state=tk.DISABLED
        )
        result_text.pack(pady=10)
    def back_to_main(self):
        self.root.destroy()
        main()

#------------------Main------------------#

def main():
    root = tk.Tk()
    root.title("AstroCrypt")
    root.geometry("750x650")
    root.configure(bg="#1E1E1E")
    root.resizable(False, False)
    icon_path = "./icon.ico"
    root.iconbitmap(icon_path)

    animation_app = ASCIIAnimation(root)

    root.mainloop()

if __name__ == "__main__":
    main()





# The Auther of this Code is Wadee-_-haddad -- Tom-Jasper
