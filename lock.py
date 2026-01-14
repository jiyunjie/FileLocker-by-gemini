import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import tkinter.font as tkfont
import os
import base64
import hashlib
import time

# --- 新增：Rich 库导入 ---
from rich.console import Console
from rich.panel import Panel
# -----------------------

from cryptography.fernet import Fernet, InvalidToken

class FileLockerApp:
    def __init__(self, root):
        self.root = root
        # --- 修改：更新版本号 ---
        self.root.title("Python 文件安全箱 v1.1 (Powered by Rich)")
        # ---------------------
        self.root.geometry("650x550")
        self.root.minsize(600, 500)

        # --- 初始化 Rich 终端控制台 ---
        self.console = Console()
        # 在终端打印一个漂亮的启动面板
        self.console.print(Panel.fit("[bold yellow]欢迎使用文件安全箱 v1.1[/]\n[dim]系统核心已加载...[/]", title="System Boot", border_style="blue"))

        # --- 定义字体 (解决中文路径报错问题) ---
        self.title_font = tkfont.Font(family="Microsoft YaHei UI", size=16, weight="bold")
        self.normal_font = tkfont.Font(family="Microsoft YaHei UI", size=10)
        self.btn_font = tkfont.Font(family="Microsoft YaHei UI", size=10)
        self.console_font = tkfont.Font(family="Consolas", size=9)

        # --- 样式设置 ---
        self.style = ttk.Style()
        available_themes = self.style.theme_names()
        if 'clam' in available_themes:
            self.style.theme_use('clam')
        
        self.style.configure('Header.TLabel', font=self.title_font)
        self.style.configure('Normal.TLabel', font=self.normal_font)
        self.style.configure('TButton', font=self.btn_font, padding=5)
        
        self.style.map('Encrypt.TButton',
            foreground=[('active', 'white'), ('!active', 'white')],
            background=[('active', '#d9534f'), ('!active', '#c9302c')]
        )
        self.style.map('Decrypt.TButton',
            foreground=[('active', 'white'), ('!active', 'white')],
            background=[('active', '#5cb85c'), ('!active', '#4cae4c')]
        )

        # --- 变量存储 ---
        self.file_path = tk.StringVar()
        
        # ================= 界面布局 =================

        # --- 顶部标题栏 ---
        title_frame = tk.Frame(root, bg="#343a40", height=50)
        title_frame.pack(fill="x")
        tk.Label(title_frame, text="🛡️ 文件加密与解密工具", font=self.title_font, fg="white", bg="#343a40").pack(pady=10)

        main_content = ttk.Frame(root, padding="20")
        main_content.pack(fill="both", expand=True)

        # --- 区域 1: 文件选择 ---
        step1_frame = ttk.LabelFrame(main_content, text="步骤 1: 选择目标文件", padding="15 10")
        step1_frame.pack(fill="x", pady=(0, 15))
        
        input_frame = ttk.Frame(step1_frame)
        input_frame.pack(fill="x")

        self.entry_path = ttk.Entry(input_frame, textvariable=self.file_path, font=self.console_font)
        self.entry_path.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        btn_browse = ttk.Button(input_frame, text="📁 浏览...", command=self.browse_file)
        btn_browse.pack(side="right")

        # --- 区域 2: 密码输入与操作 ---
        step2_frame = ttk.LabelFrame(main_content, text="步骤 2: 安全凭证与操作", padding="15 10")
        step2_frame.pack(fill="x", pady=(0, 15))

        ttk.Label(step2_frame, text="输入密码:", style='Normal.TLabel').pack(anchor="w")
        self.entry_password = ttk.Entry(step2_frame, show="•", font=self.normal_font, width=40)
        self.entry_password.pack(fill="x", pady=(5, 15))

        # 按钮区域
        btns_frame = ttk.Frame(step2_frame)
        btns_frame.pack()
        
        btn_encrypt = ttk.Button(btns_frame, text="🔒 立刻加密 (Lock)", style='Encrypt.TButton', command=self.encrypt_file, width=18)
        btn_encrypt.pack(side="left", padx=20)
        
        btn_decrypt = ttk.Button(btns_frame, text="🔓 立刻解密 (Unlock)", style='Decrypt.TButton', command=self.decrypt_file, width=18)
        btn_decrypt.pack(side="left", padx=20)

        # --- 区域 3: 操作日志/进度展示 ---
        log_frame_container = ttk.LabelFrame(main_content, text="操作日志与进度监控", padding="10")
        log_frame_container.pack(fill="both", expand=True)
        
        self.log_area = scrolledtext.ScrolledText(log_frame_container, height=8, state='disabled', bg="#f8f9fa", font=self.console_font)
        self.log_area.pack(fill="both", expand=True)
        
        # 初始日志
        self.log_message("系统就绪。请选择文件并输入密码。", "info")

    # ================= 辅助功能 =================

    def log_message(self, message, tag=None):
        """
        双重日志系统：
        1. GUI 界面显示 (Tkinter)
        2. 终端彩色显示 (Rich)
        """
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        
        # --- 1. 更新 GUI 界面 ---
        self.log_area.config(state='normal')
        if tag:
             self.log_area.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        else:
             self.log_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')
        self.root.update() # 强制刷新界面

        # --- 2. 更新 Rich 终端 (v1.1 新功能) ---
        rich_style = "white"
        prefix = "📝"
        
        if tag == "success":
            rich_style = "bold green"
            prefix = "✅"
        elif tag == "error":
            rich_style = "bold red"
            prefix = "❌"
        elif tag == "info":
            rich_style = "bold cyan"
            prefix = "ℹ️ "
        elif tag == "warning":
            rich_style = "bold yellow"
            prefix = "⚠️ "

        # 在终端打印
        self.console.print(f"[{rich_style}]{prefix} [{timestamp}] {message}[/]")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            self.log_message(f"已选择文件: {os.path.basename(filename)}")

    def get_key_from_password(self, password):
        self.log_message("正在利用 SHA-256 算法生成密钥...", "info")
        digest = hashlib.sha256(password.encode()).digest()
        key = base64.urlsafe_b64encode(digest)
        return key

    # ================= 核心逻辑 =================

    def encrypt_file(self):
        file_path = self.file_path.get()
        password = self.entry_password.get()

        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("错误", "请先选择一个有效的文件！")
            return
        if not password:
            messagebox.showerror("错误", "请输入密码！")
            self.entry_password.focus()
            return

        self.log_message(">>> 开始加密流程 <<<", "info")
        # 在 GUI 设置颜色标签
        self.log_area.tag_config("success", foreground="green")
        self.log_area.tag_config("error", foreground="red")
        self.log_area.tag_config("info", foreground="blue")
        self.log_area.tag_config("warning", foreground="#ffae00")

        try:
            key = self.get_key_from_password(password)
            fernet = Fernet(key)

            file_size = os.path.getsize(file_path)
            self.log_message(f"读取源文件 ({file_size} bytes)...")
            with open(file_path, 'rb') as f:
                original_data = f.read()

            self.log_message("执行 AES 对称加密...", "info")
            encrypted_data = fernet.encrypt(original_data)

            new_path = file_path + ".lock"
            self.log_message(f"写入加密文件: {os.path.basename(new_path)}...")
            with open(new_path, 'wb') as f:
                f.write(encrypted_data)

            self.log_message(f"加密成功！已生成 .lock 文件。", "success")
            self.log_message(">>> 流程结束 <<<", "info")
            messagebox.showinfo("成功", f"文件已加密！\n保存在: {new_path}")
            self.file_path.set(new_path)
            
        except Exception as e:
            err_msg = f"加密失败: {str(e)}"
            self.log_message(err_msg, "error")
            messagebox.showerror("错误", err_msg)

    def decrypt_file(self):
        file_path = self.file_path.get()
        password = self.entry_password.get()

        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("错误", "请选择文件！")
            return
        if not file_path.endswith(".lock"):
            messagebox.showwarning("警告", "请选择以 .lock 结尾的加密文件进行解密。")
            self.log_message("警告：尝试解密非 .lock 文件。", "warning")
            return
        if not password:
            messagebox.showerror("错误", "请输入密码！")
            return

        self.log_message(">>> 开始解密流程 <<<", "info")
        self.log_area.tag_config("success", foreground="green")
        self.log_area.tag_config("error", foreground="red")
        self.log_area.tag_config("info", foreground="blue")
        self.log_area.tag_config("warning", foreground="#ffae00")

        try:
            key = self.get_key_from_password(password)
            fernet = Fernet(key)

            self.log_message("读取加密文件内容...")
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            self.log_message("验证密码并解密数据...", "info")
            decrypted_data = fernet.decrypt(encrypted_data)
            self.log_message("密码验证通过，解密成功。", "success")

            original_path = file_path[:-5] 
            self.log_message(f"还原原始文件: {os.path.basename(original_path)}...")
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)

            self.log_message(f"解密完成！文件已还原。", "success")
            self.log_message(">>> 流程结束 <<<", "info")
            messagebox.showinfo("成功", f"文件已成功解密！\n还原为: {original_path}")
            self.file_path.set(original_path)

        except InvalidToken:
            self.log_message("解密失败：密码错误或文件已损坏！", "error")
            messagebox.showerror("错误", "解密失败：密码错误！\n无法验证文件签名。")
        except Exception as e:
            err_msg = f"解密过程中出错: {str(e)}"
            self.log_message(err_msg, "error")
            messagebox.showerror("错误", err_msg)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileLockerApp(root)
    root.mainloop()