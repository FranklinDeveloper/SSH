# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import hashlib
import base64
import re
import logging
import paramiko
import ctypes
from PIL import Image, ImageTk
import tempfile
import webbrowser
import json
import urllib.request
import shutil
import socket
import glob
import traceback
import fnmatch
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag
from packaging import version
from datetime import datetime

# Verificar se está rodando como executável empacotado (exe)
IS_EXE = getattr(sys, 'frozen', False)

# Versão do software
SOFTWARE_VERSION = "1.2.13"

# Oculta o console ao iniciar o .exe (Windows apenas)
if sys.platform.startswith('win') and IS_EXE:
    console_handle = ctypes.windll.kernel32.GetConsoleWindow()
    if console_handle:
        ctypes.windll.user32.ShowWindow(console_handle, 0)

# Configuração básica de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ssh_tool')

# Filtros padrão (serão sobrescritos pela configuração)
DEFAULT_FILTER_USERS = ['root', 'zabbix', 'sshd', 'postfix', 'nscd', 'message+', 'usertra+', 'prod', 'fatura', 'logist', 'lp']
DEFAULT_FILTER_COMMANDS = [
    '(sd-pam)', 
    '-bash', 
    '/opt/microfocu', 
    '/opt/microfocus', 
    '/usr/lib/system', 
    'bash', 
    'pg /d/work/est2', 
    'ps aux', 
    'sh /app/scripts', 
    'sh /usr/bin/cha', 
    '/usr/lib/ssh/sf',
    '/opt/',
    'pg -f'
]

class AutoUpdater:
    """Sistema robusto de auto-atualização"""
    def __init__(self, gui_instance):
        self.gui = gui_instance
        self.current_version = SOFTWARE_VERSION
        self.update_in_progress = False

    def get_github_data(self, url):
        """Obtém dados da API do GitHub SEM autenticação"""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SSHClientGUI"
        }
        
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                logger.error("Erro 403: Limite de requisições excedido no GitHub")
            elif e.code == 401:
                logger.error("Erro 401: Acesso não autorizado (repositório público?)")
            else:
                logger.error(f"Erro HTTP {e.code}: {e.reason}")
        except Exception as e:
            logger.error(f"Erro na conexão: {str(e)}")
        return None

    def download_asset(self, asset_url, save_path):
        """Baixa um asset do GitHub SEM autenticação"""
        try:
            headers = {
                "Accept": "application/octet-stream",
                "User-Agent": "SSHClientGUI"
            }
            
            req = urllib.request.Request(asset_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                chunk_size = 8192
                
                with open(save_path, 'wb') as out_file:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        out_file.write(chunk)
                        downloaded += len(chunk)
                        
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            self.gui.update_status(f"Baixando: {progress:.1f}%", "progress")
            
            return True
        except Exception as e:
            logger.error(f"Erro no download: {str(e)}")
            return False

    def verify_file_integrity(self, file_path, expected_hash):
        """Verifica a integridade do arquivo com SHA-256"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
                    
            return sha256.hexdigest().lower() == expected_hash.lower()
        except Exception as e:
            logger.error(f"Erro na verificação: {str(e)}")
            return False

    def apply_update(self, temp_file):
        """Substitui o executável atual pela nova versão usando um script batch"""
        try:
            current_exe = sys.executable
            temp_dir = os.path.dirname(temp_file)
            
            # Criar um script batch para realizar a substituição
            batch_script = os.path.join(temp_dir, "update.bat")
            with open(batch_script, 'w') as bat_file:
                bat_file.write("@echo off\n")
                bat_file.write("echo Aguardando o término do processo atual...\n")
                bat_file.write(":loop\n")
                bat_file.write(f'tasklist /FI "IMAGENAME eq {os.path.basename(current_exe)}" | find "{os.path.basename(current_exe)}" > nul\n')
                bat_file.write("if not errorlevel 1 (\n")
                bat_file.write("  timeout /t 1 /nobreak > nul\n")
                bat_file.write("  goto loop\n")
                bat_file.write(")\n\n")
                # Fazer backup do atual
                bat_file.write(f'if exist "{current_exe}.bak" del "{current_exe}.bak"\n')
                bat_file.write(f'copy "{current_exe}" "{current_exe}.bak" > nul\n')
                # Substituir o executável
                bat_file.write(f'move /Y "{temp_file}" "{current_exe}" > nul\n')
                # Excluir o script
                bat_file.write(f'del "%~f0"\n')
            
            # Executar o script batch em segundo plano
            creation_flags = subprocess.CREATE_NO_WINDOW
            subprocess.Popen(
                [batch_script], 
                shell=True, 
                creationflags=creation_flags,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return True
        except Exception as e:
            logger.error(f"Erro na aplicação da atualização: {str(e)}")
            return False

class InteractiveHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Política interativa para verificação de host keys"""
    def __init__(self, root, port=22):
        self.root = root
        self.port = port
        super().__init__()
    
    def missing_host_key(self, client, hostname, key):
        """Trata chaves de host desconhecidas"""
        fp = hashlib.sha256(key.asbytes()).digest()
        fp_base64 = base64.b64encode(fp).rstrip(b'=').decode('ascii')
        
        top = tk.Toplevel(self.root)
        top.title("Verificação de Segurança")
        top.geometry("600x250")
        top.resizable(False, False)
        top.transient(self.root)
        top.grab_set()
        
        frame = ttk.Frame(top, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        msg = (
            f"ATENÇÃO: Host desconhecido '{hostname}'!\n\n"
            f"Fingerprint (SHA256): {fp_base64}\n\n"
            "Deseja confiar neste host?"
        )
        ttk.Label(frame, text=msg).pack(pady=10)
        
        self.remember_var = tk.BooleanVar(value=True)
        save_check = ttk.Checkbutton(
            frame, 
            text="Lembrar este host permanentemente",
            variable=self.remember_var
        )
        save_check.pack(pady=5)
        
        user_response = None
        
        def handle_response(response):
            nonlocal user_response
            user_response = response
            top.destroy()
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Sim", command=lambda: handle_response(True)).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Não", command=lambda: handle_response(False)).pack(side=tk.LEFT, padx=10)
        
        top.update_idletasks()
        width = top.winfo_width()
        height = top.winfo_height()
        x = (top.winfo_screenwidth() // 2) - (width // 2)
        y = (top.winfo_screenheight() // 2) - (height // 2)
        top.geometry(f"{width}x{height}+{x}+{y}")
        
        self.root.wait_window(top)
        
        if not user_response:
            raise paramiko.SSHException(f"Host {hostname} rejeitado pelo usuário")
        
        client._host_keys.add(hostname, key.get_name(), key)
        
        if self.remember_var.get():
            try:
                known_hosts = os.path.expanduser("~/.ssh/known_hosts")
                os.makedirs(os.path.dirname(known_hosts), exist_ok=True)
                
                if self.port != 22:
                    host_key = f"[{hostname}]:{self.port}"
                else:
                    host_key = hostname
                
                with open(known_hosts, 'a') as f:
                    f.write(f"{host_key} {key.get_name()} {key.get_base64()}\n")
                
                messagebox.showinfo("Sucesso", 
                    f"Host {host_key} adicionado permanentemente ao arquivo known_hosts")
            except Exception as e:
                messagebox.showerror("Erro", 
                    f"Falha ao salvar no known_hosts: {str(e)}")

class SSHClientGUI:
    """Interface gráfica para cliente SSH"""
    def __init__(self, root):
        self.root = root
        self.root.title(f"Gerenciador SSH Avançado v{SOFTWARE_VERSION}")
        self.root.geometry("950x600")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        self.ico_path = None
        self.temp_ico_file = None
        self.load_application_icon()
        
        # Inicializa o sistema de auto-atualização
        self.updater = AutoUpdater(self)
        
        self.all_processes = []
        self.host_history = []
        self.admin_config_file = os.path.join(os.path.expanduser("~"), ".ssh_tool_config")
        self.admin_config = self.load_admin_config()
        self.permanent_filter = {
            'users': self.admin_config.get('permanent_filter_users', DEFAULT_FILTER_USERS),
            'commands': self.admin_config.get('permanent_filter_commands', DEFAULT_FILTER_COMMANDS)
        }
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TNotebook.Tab', background="#626669", foreground='white')
        self.style.map('TNotebook.Tab', background=[('selected', "#42a707")])
        self.style.configure('.', font=('Segoe UI', 10))
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0')
        self.style.configure('TLabelframe', background='#f0f0f0')
        self.style.configure('TLabelframe.Label', background='#f0f0f0')
        self.style.configure('Treeview', rowheight=25, font=('Consolas', 9))
        self.style.map('Treeview', background=[('selected', '#0078d7')])
        self.style.configure('Treeview.Heading', font=('Segoe UI', 9, 'bold'))
        self.style.configure('TButton', font=('Segoe UI', 9))
        self.style.configure('Red.TButton', foreground='white', background='#d9534f')
        self.style.map('Red.TButton', 
                      background=[('active', '#c9302c'), ('disabled', '#f5c6cb')])
        self.style.configure('Green.TButton', foreground='white', background='#5cb85c')
        self.style.map('Green.TButton', 
                      background=[('active', '#4cae4c'), ('disabled', '#c3e6cb')])
        self.style.configure('Blue.TButton', foreground='white', background='#007bff')
        self.style.map('Blue.TButton', 
                      background=[('active', '#0069d9'), ('disabled', '#b3d7ff')])
        
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.client = None
        self.shell = None
        self.current_host = None
        self.stop_receiver = threading.Event()
        self.receiver_thread = None
        self.running = True
        self.show_password = False
        self.caps_lock_warning_shown = False
        
        conn_frame = ttk.LabelFrame(main_frame, text="Configuração de Conexão")
        conn_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(conn_frame, text="Host:").grid(row=0, column=0, padx=3, pady=2, sticky=tk.W)
        self.host_var = tk.StringVar(value="mg01.grp.local")
        self.host_combo = ttk.Combobox(conn_frame, textvariable=self.host_var, width=15)
        self.host_combo.grid(row=0, column=1, padx=3, pady=2, sticky=tk.W)
        self.host_combo['values'] = self.load_host_history()
        self.host_combo.bind("<<ComboboxSelected>>", self.on_host_selected)
        self.host_combo.bind("<Return>", lambda event: self.connect())
        
        ttk.Label(conn_frame, text="Usuário:").grid(row=0, column=2, padx=(8,3), pady=2, sticky=tk.W)
        self.user_var = tk.StringVar(value="prod")
        user_entry = ttk.Entry(conn_frame, textvariable=self.user_var, width=10)
        user_entry.grid(row=0, column=3, padx=3, pady=2, sticky=tk.W)
        user_entry.bind("<Return>", lambda event: self.connect())
        
        ttk.Label(conn_frame, text="Senha:").grid(row=0, column=4, padx=(8,3), pady=2, sticky=tk.W)
        
        password_frame = ttk.Frame(conn_frame)
        password_frame.grid(row=0, column=5, padx=3, pady=2, sticky=tk.W)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=10)
        self.password_entry.pack(side=tk.LEFT)
        self.password_entry.bind("<Return>", lambda event: self.connect())
        
        self.eye_button = ttk.Button(
            password_frame, 
            text="\U0001F441",  # Olho Unicode
            width=2, 
            command=self.toggle_password_visibility
        )
        self.eye_button.pack(side=tk.LEFT, padx=(2,0))
        self.password_entry.bind("<FocusIn>", self.on_password_focus_in)
        self.password_entry.bind("<KeyRelease>", self.on_password_key_release)
        
        ttk.Label(conn_frame, text="Porta:").grid(row=0, column=6, padx=(8,3), pady=2, sticky=tk.W)
        self.port_var = tk.StringVar(value="22")
        port_entry = ttk.Entry(conn_frame, textvariable=self.port_var, width=4)
        port_entry.grid(row=0, column=7, padx=3, pady=2, sticky=tk.W)
        port_entry.bind("<Return>", lambda event: self.connect())
        
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.grid(row=0, column=8, padx=(10,3), pady=2, sticky=tk.E)
        
        self.connect_btn = ttk.Button(btn_frame, text="Conectar", 
                                     command=self.connect, style='Green.TButton', width=9)
        self.connect_btn.pack(side=tk.LEFT, padx=2)
        
        self.disconnect_btn = ttk.Button(btn_frame, text="Desconectar", 
                                        command=self.disconnect, state=tk.DISABLED,
                                        style='Red.TButton', width=12)
        self.disconnect_btn.pack(side=tk.LEFT, padx=2)
        
        self.admin_btn = ttk.Button(
            btn_frame, 
            text="Administrador",
            command=self.show_admin_dialog,
            style='Blue.TButton',
            width=14
        )
        self.admin_btn.pack(side=tk.LEFT, padx=2)
        
        help_btn = ttk.Button(
            btn_frame, 
            text="Ajuda?",
            command=self.show_help,
            width=6
        )
        help_btn.pack(side=tk.LEFT, padx=2)
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Aba Derrubar Conf
        pid_frame = ttk.Frame(self.notebook)
        self.notebook.add(pid_frame, text=" Derrubar Conf ")
        top_frame = ttk.Frame(pid_frame)
        top_frame.pack(fill=tk.X, padx=5, pady=2)
        action_frame = ttk.Frame(top_frame)
        action_frame.pack(side=tk.LEFT, padx=(0,5))
        list_btn = ttk.Button(action_frame, text="Listar Processos", 
                  command=self.list_processes, width=15)
        list_btn.pack(side=tk.TOP, pady=1)
        refresh_btn = ttk.Button(action_frame, text="Atualizar Lista", 
                  command=self.list_processes, width=15)
        refresh_btn.pack(side=tk.TOP, pady=1)
        filter_frame = ttk.LabelFrame(top_frame, text="Filtros")
        filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=0)
        ttk.Label(filter_frame, text="Usuário:").pack(side=tk.LEFT, padx=(5,2))
        self.user_filter_var = tk.StringVar()
        user_filter_entry = ttk.Entry(filter_frame, textvariable=self.user_filter_var, width=10)
        user_filter_entry.pack(side=tk.LEFT, padx=(0,3))
        user_filter_entry.bind("<Return>", lambda event: self.apply_filters())
        ttk.Label(filter_frame, text="PID:").pack(side=tk.LEFT, padx=(5,2))
        self.pid_filter_var = tk.StringVar()
        pid_filter_entry = ttk.Entry(filter_frame, textvariable=self.pid_filter_var, width=6)
        pid_filter_entry.pack(side=tk.LEFT, padx=(0,3))
        pid_filter_entry.bind("<Return>", lambda event: self.apply_filters())
        ttk.Label(filter_frame, text="Command:").pack(side=tk.LEFT, padx=(5,2))
        self.cmd_filter_var = tk.StringVar()
        cmd_filter_entry = ttk.Entry(filter_frame, textvariable=self.cmd_filter_var, width=15)
        cmd_filter_entry.pack(side=tk.LEFT, padx=(0,3))
        cmd_filter_entry.bind("<Return>", lambda event: self.apply_filters())
        apply_btn = ttk.Button(filter_frame, text="Aplicar Filtros", 
                  command=self.apply_filters, width=12)
        apply_btn.pack(side=tk.LEFT, padx=2)
        clear_btn = ttk.Button(filter_frame, text="Limpar Filtros", 
                  command=self.clear_filters, width=12)
        clear_btn.pack(side=tk.LEFT)
        input_frame = ttk.LabelFrame(pid_frame, text="Seleção de PIDs")
        input_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(input_frame, 
                 text="Selecione PIDs na tabela ou digite manualmente (separados por espaço):").pack(anchor=tk.W, padx=5, pady=(2,0))
        self.pids_var = tk.StringVar()
        self.pids_entry = ttk.Entry(input_frame, textvariable=self.pids_var)
        self.pids_entry.pack(fill=tk.X, padx=5, pady=2)
        self.pids_entry.bind("<Return>", lambda event: self.kill_pids())
        btn_action_frame = ttk.Frame(input_frame)
        btn_action_frame.pack(fill=tk.X, pady=(0,2))
        self.kill_button = ttk.Button(
            btn_action_frame, 
            text="Derrubar PIDs Selecionados", 
            command=self.kill_pids, 
            style='Red.TButton',
            width=20
        )
        self.kill_button.pack(side=tk.LEFT, padx=2)
        self.clear_button = ttk.Button(
            btn_action_frame, 
            text="Limpar Seleção",
            command=lambda: self.pids_var.set(""),
            width=15
        )
        self.clear_button.pack(side=tk.LEFT, padx=2)
        tree_frame = ttk.Frame(pid_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0,2))
        columns = ('user', 'pid', 'idle', 'command')
        self.process_tree = ttk.Treeview(
            tree_frame, columns=columns, show='headings', selectmode='extended'
        )
        col_widths = [100, 70, 70, 380]
        for idx, col in enumerate(columns):
            self.process_tree.heading(
                col, 
                text=col.upper(), 
                anchor=tk.W,
                command=lambda c=col: self.treeview_sort_column(self.process_tree, c, False)
            )
            self.process_tree.column(col, width=col_widths[idx], anchor=tk.W)
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.process_tree.bind('<<TreeviewSelect>>', self.on_pid_select)
        
        # Aba Derrubar Matrícula e Romaneio
        matricula_frame = ttk.Frame(self.notebook)
        self.notebook.add(matricula_frame, text=" Derrubar Matrícula e Romaneio ")
        input_frame = ttk.LabelFrame(matricula_frame, text="Consulta de PID")
        input_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(input_frame, text="Matrícula ou Romaneio:").pack(side=tk.LEFT, padx=(5,2))
        self.matricula_var = tk.StringVar()
        matricula_entry = ttk.Entry(input_frame, textvariable=self.matricula_var, width=15)
        matricula_entry.pack(side=tk.LEFT, padx=(0,5))
        matricula_entry.bind("<Return>", lambda event: self.consultar_matricula())
        self.consultar_matricula_btn = ttk.Button(
            input_frame, 
            text="Consultar", 
            command=self.consultar_matricula,
            width=10
        )
        self.consultar_matricula_btn.pack(side=tk.LEFT)
        status_frame = ttk.LabelFrame(matricula_frame, text="Status da Operação")
        status_frame.pack(fill=tk.X, padx=5, pady=2)
        self.matricula_status_var = tk.StringVar(value="Aguardando operação...")
        ttk.Label(
            status_frame, 
            textvariable=self.matricula_status_var,
            font=('Segoe UI', 9, 'italic'),
            wraplength=900
        ).pack(fill=tk.X, padx=5, pady=2)
        pid_select_frame = ttk.LabelFrame(matricula_frame, text="Seleção de PIDs")
        pid_select_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(pid_select_frame, 
                 text="Selecione PIDs na tabela ou digite manualmente (separados por espaço):").pack(anchor=tk.W, padx=5, pady=(2,0))
        self.matricula_pids_var = tk.StringVar()
        self.matricula_pids_entry = ttk.Entry(pid_select_frame, textvariable=self.matricula_pids_var)
        self.matricula_pids_entry.pack(fill=tk.X, padx=5, pady=2)
        self.matricula_pids_entry.bind("<Return>", lambda event: self.derrubar_pid_selecionado())
        btn_action_frame = ttk.Frame(pid_select_frame)
        btn_action_frame.pack(fill=tk.X, pady=(0,2))
        self.derrubar_pid_selecionado_btn = ttk.Button(
            btn_action_frame, 
            text="Derrubar PIDs Selecionados", 
            command=self.derrubar_pid_selecionado,
            style='Red.TButton',
            width=20
        )
        self.derrubar_pid_selecionado_btn.pack(side=tk.LEFT, padx=2)
        self.clear_matricula_button = ttk.Button(
            btn_action_frame, 
            text="Limpar Seleção",
            command=lambda: self.matricula_pids_var.set(""),
            width=15
        )
        self.clear_matricula_button.pack(side=tk.LEFT, padx=2)
        result_frame = ttk.LabelFrame(matricula_frame, text="Resultados da Consulta")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        columns = ('user', 'pid', 'name')
        self.result_tree = ttk.Treeview(
            result_frame, 
            columns=columns, 
            show='headings',
            selectmode='extended'
        )
        col_widths = [80, 60, 400]
        for idx, col in enumerate(columns):
            self.result_tree.heading(
                col, 
                text=col.upper(), 
                anchor=tk.W,
                command=lambda c=col: self.treeview_sort_column(self.result_tree, c, False)
            )
            self.result_tree.column(col, width=col_widths[idx], anchor=tk.W)
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.result_tree.bind('<<TreeviewSelect>>', self.on_matricula_pid_select)
        
        # Aba Consultar Tela
        tela_frame = ttk.Frame(self.notebook)
        self.notebook.add(tela_frame, text=" Consultar Tela ")
        input_frame_tela = ttk.LabelFrame(tela_frame, text="Consulta de PID")
        input_frame_tela.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(input_frame_tela, text="Tela:").pack(side=tk.LEFT, padx=(5,2))
        self.tela_var = tk.StringVar(value="*")
        tela_entry = ttk.Entry(input_frame_tela, textvariable=self.tela_var, width=15)
        tela_entry.pack(side=tk.LEFT, padx=(0,5))
        tela_entry.bind("<Return>", lambda event: self.consultar_tela())
        self.consultar_tela_btn = ttk.Button(
            input_frame_tela, 
            text="Consultar Tela", 
            command=self.consultar_tela,
            width=13
        )
        self.consultar_tela_btn.pack(side=tk.LEFT)
        status_frame_tela = ttk.LabelFrame(tela_frame, text="Status da Operação")
        status_frame_tela.pack(fill=tk.X, padx=5, pady=2)
        self.tela_status_var = tk.StringVar(value="Aguardando operação...")
        ttk.Label(
            status_frame_tela, 
            textvariable=self.tela_status_var,
            font=('Segoe UI', 9, 'italic'),
            wraplength=900
        ).pack(fill=tk.X, padx=5, pady=2)
        pid_select_frame_tela = ttk.LabelFrame(tela_frame, text="Seleção de PIDs")
        pid_select_frame_tela.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(pid_select_frame_tela, 
                 text="Selecione PIDs na tabela ou digite manualmente (separados por espaço):").pack(anchor=tk.W, padx=5, pady=(2,0))
        self.tela_pids_var = tk.StringVar()
        self.tela_pids_entry = ttk.Entry(pid_select_frame_tela, textvariable=self.tela_pids_var)
        self.tela_pids_entry.pack(fill=tk.X, padx=5, pady=2)
        self.tela_pids_entry.bind("<Return>", lambda event: self.derrubar_pid_tela())
        btn_action_frame_tela = ttk.Frame(pid_select_frame_tela)
        btn_action_frame_tela.pack(fill=tk.X, pady=(0,2))
        self.derrubar_pid_tela_btn = ttk.Button(
            btn_action_frame_tela, 
            text="Derrubar PIDs Selecionados", 
            command=self.derrubar_pid_tela,
            style='Red.TButton',
            width=20
        )
        self.derrubar_pid_tela_btn.pack(side=tk.LEFT, padx=2)
        self.clear_tela_button = ttk.Button(
            btn_action_frame_tela, 
            text="Limpar Seleção",
            command=lambda: self.tela_pids_var.set(""),
            width=15
        )
        self.clear_tela_button.pack(side=tk.LEFT, padx=2)
        result_frame_tela = ttk.LabelFrame(tela_frame, text="Resultados da Consulta")
        result_frame_tela.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        columns = ('user', 'pid', 'name')
        self.tela_tree = ttk.Treeview(
            result_frame_tela, 
            columns=columns, 
            show='headings',
            selectmode='extended'
        )
        col_widths = [80, 60, 400]
        for idx, col in enumerate(columns):
            self.tela_tree.heading(
                col, 
                text=col.upper(), 
                anchor=tk.W,
                command=lambda c=col: self.treeview_sort_column(self.tela_tree, c, False)
            )
            self.tela_tree.column(col, width=col_widths[idx], anchor=tk.W)
        scrollbar_tela = ttk.Scrollbar(result_frame_tela, orient=tk.VERTICAL, command=self.tela_tree.yview)
        self.tela_tree.configure(yscroll=scrollbar_tela.set)
        scrollbar_tela.pack(side=tk.RIGHT, fill=tk.Y)
        self.tela_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tela_tree.bind('<<TreeviewSelect>>', self.on_tela_pid_select)
        
        # Aba Terminal Interativo
        terminal_frame = ttk.Frame(self.notebook)
        self.notebook.add(terminal_frame, text=" Terminal Interativo ")
        self.output_text = scrolledtext.ScrolledText(
            terminal_frame, wrap=tk.WORD, bg='#1e1e1e', fg='#d4d4d4', 
            insertbackground='white', font=('Consolas', 10)
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        self.output_text.config(state=tk.DISABLED)
        cmd_frame = ttk.Frame(terminal_frame)
        cmd_frame.pack(fill=tk.X, padx=5, pady=(0,2))
        ttk.Label(cmd_frame, text="Comando:").pack(side=tk.LEFT, padx=(0,5))
        self.cmd_var = tk.StringVar()
        self.cmd_entry = ttk.Entry(cmd_frame, textvariable=self.cmd_var, width=40)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        self.cmd_entry.bind("<Return>", self.send_command)
        send_btn = ttk.Button(cmd_frame, text="Enviar", command=self.send_command)
        send_btn.pack(side=tk.LEFT)
        
        # Aba Executar Comandos
        commands_frame = ttk.Frame(self.notebook)
        self.notebook.add(commands_frame, text=" Executar Comandos ")
        cmd_input_frame = ttk.Frame(commands_frame)
        cmd_input_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(cmd_input_frame, text="Comandos (um por linha):").pack(anchor=tk.W, pady=(0,2))
        self.commands_text = scrolledtext.ScrolledText(cmd_input_frame, height=6, font=('Consolas', 9))
        self.commands_text.pack(fill=tk.X, pady=(0,2))
        self.commands_text.insert(tk.END, "ls -la\necho \"Teste SSH\"\nwhoami")
        exec_btn = ttk.Button(
            cmd_input_frame, text="Executar Comandos", command=self.execute_commands
        )
        exec_btn.pack(anchor=tk.E, pady=2)
        result_frame = ttk.Frame(commands_frame)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0,2))
        ttk.Label(result_frame, text="Resultados:", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)
        self.result_text = scrolledtext.ScrolledText(
            result_frame, wrap=tk.WORD, bg='#1e1e1e', fg='#d4d4d4', 
            font=('Consolas', 10), state=tk.DISABLED
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)
        self.password_entry.focus_set()
        
        # Rodapé
        footer_frame = ttk.Frame(root, relief=tk.SUNKEN, padding=(5, 3))
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.connection_status = tk.StringVar(value="Status: Desconectado")
        self.status_label = ttk.Label(footer_frame, textvariable=self.connection_status)
        self.status_label.pack(side=tk.LEFT, padx=5)
        copyright_frame = ttk.Frame(footer_frame)
        copyright_frame.pack(side=tk.RIGHT, padx=5)
        ttk.Label(copyright_frame, text=f"© 2024 Franklin Tadeu v{SOFTWARE_VERSION}").pack(side=tk.LEFT)
        link_label = ttk.Label(
            copyright_frame, 
            text="LinkedIn", 
            foreground="blue", 
            cursor="hand2"
        )
        link_label.pack(side=tk.LEFT, padx=(5, 0))
        link_label.bind("<Button-1>", lambda e: webbrowser.open("https://www.linkedin.com/in/franklintadeu/"))
        contact_frame = ttk.Frame(footer_frame)
        contact_frame.pack(side=tk.RIGHT, padx=5)
        ttk.Label(contact_frame, text="Contato:").pack(side=tk.LEFT, padx=(5,0))
        whatsapp_label = ttk.Label(
            contact_frame, 
            text="31 99363-9500", 
            foreground="blue", 
            cursor="hand2"
        )
        whatsapp_label.pack(side=tk.LEFT, padx=(0,5))
        whatsapp_label.bind("<Button-1>", lambda e: webbrowser.open("https://wa.me/5531993639500"))
        root.protocol("WM_DELETE_WINDOW", self.safe_close)

        self.capturing_matricula = False
        self.matricula_output = ""
        self.capturing_tela = False
        self.tela_output = ""
        self.setup_treeview_bindings()
        
        # Verificar se há uma versão anterior em execução
        self.check_and_kill_old_versions()

    def check_and_kill_old_versions(self):
        """Encerra versões anteriores do aplicativo"""
        current_pid = os.getpid()
        current_exe = os.path.basename(sys.executable).lower()
        
        try:
            # Listar todos os processos
            if sys.platform.startswith('win'):
                cmd = 'tasklist /FO CSV /NH'
                output = subprocess.check_output(cmd, shell=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                processes = [line.split(',')[0].strip('"') for line in output.splitlines() if line.strip()]
            else:
                cmd = 'ps -eo comm='
                output = subprocess.check_output(cmd, shell=True, text=True)
                processes = output.splitlines()
            
            # Filtra processos com mesmo nome mas PID diferente
            for proc_name in processes:
                if proc_name.lower() == current_exe:
                    try:
                        # Obter PID do processo
                        if sys.platform.startswith('win'):
                            cmd = f'tasklist /FI "IMAGENAME eq {proc_name}" /FO CSV /NH'
                            out = subprocess.check_output(cmd, shell=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                            for line in out.splitlines():
                                parts = line.split(',')
                                if len(parts) >= 2:
                                    pid = int(parts[1].strip('"'))
                                    if pid != current_pid:
                                        os.kill(pid, 9)
                        else:
                            cmd = f'pgrep -f "{proc_name}"'
                            out = subprocess.check_output(cmd, shell=True, text=True)
                            for pid in out.split():
                                pid = int(pid)
                                if pid != current_pid:
                                    os.kill(pid, 9)
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"Erro ao verificar processos antigos: {str(e)}")

    def setup_treeview_bindings(self):
        """Configura atalhos de teclado para as treeviews"""
        for tree in [self.process_tree, self.result_tree, self.tela_tree]:
            tree.bind("<Control-a>", self.select_all_treeview)
            tree.bind("<Control-A>", self.select_all_treeview)

    def select_all_treeview(self, event):
        """Seleciona todos os itens da treeview com Ctrl+A"""
        tree = event.widget
        tree.selection_set(tree.get_children())
        return "break"

    def update_status(self, message, msg_type=None):
        """Atualiza a barra de status"""
        self.connection_status.set(message)
        
        # Atualiza cores baseadas no tipo de mensagem
        if msg_type == "error":
            self.status_label.configure(background="#ffcccc", foreground="black")
        elif msg_type == "success":
            self.status_label.configure(background="#ccffcc", foreground="black")
        elif msg_type == "progress":
            self.status_label.configure(background="#ffffcc", foreground="black")
        elif msg_type == "warning":
            self.status_label.configure(background="#ffcc99", foreground="black")
        else:
            self.status_label.configure(background="#f0f0f0", foreground="black")
        
        # Atualiza o log
        logger.info(f"[STATUS] {message}")

    @classmethod
    def generate_salt(cls):
        hostname = socket.gethostname().encode()
        return hashlib.sha256(hostname).digest()[:16]

    @staticmethod
    def get_master_key():
        # Geração segura de chave
        return os.urandom(32)  # 256 bits de entropia

    @classmethod
    def derive_key(cls, salt=None):
        if salt is None:
            salt = cls.generate_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            iterations=100000,
            backend=default_backend
        )
        return kdf.derive(cls.get_master_key())

    @classmethod
    def encrypt_data(cls, plaintext):
        try:
            salt = cls.generate_salt()
            key = cls.derive_key(salt)
            aes_key = key[:32]
            hmac_key = key[32:]
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            tag = encryptor.tag
            return base64.b64encode(salt + iv + ciphertext + tag).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return plaintext

    @classmethod
    def decrypt_data(cls, ciphertext_b64):
        try:
            data = base64.b64decode(ciphertext_b64)
            if len(data) < (16 + 16 + 16):  # salt (16) + iv (16) + tag (16)
                logger.error("Decryption error: Data too short")
                return ciphertext_b64
            salt = data[:16]
            iv = data[16:32]
            ciphertext = data[32:-16]
            tag = data[-16:]
            key = cls.derive_key(salt)
            aes_key = key[:32]
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            try:
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                return plaintext.decode()
            except ValueError as e:
                logger.error(f"Padding error: {e}")
                return padded_plaintext.decode(errors='ignore')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return ciphertext_b64

    def load_admin_config(self):
        default_config = {
            'admin_password': self.encrypt_data('admin'),
            'update_url': "",
            'permanent_filter_users': DEFAULT_FILTER_USERS,
            'permanent_filter_commands': DEFAULT_FILTER_COMMANDS
        }
        config_path = self.admin_config_file
        if not os.path.exists(config_path):
            return default_config
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
            return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return default_config

    def save_admin_config(self, config):
        config_to_save = config.copy()
        if 'admin_password' in config_to_save and not re.match(r'^[A-Za-z0-9+/]+={0,2}$', config_to_save['admin_password']):
            config_to_save['admin_password'] = self.encrypt_data(config_to_save['admin_password'])
        try:
            with open(self.admin_config_file, 'w') as f:
                json.dump(config_to_save, f)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False

    def load_application_icon(self):
        """Carrega o ícone para todas as janelas"""
        self.ico_path = self.find_application_icon()
        if self.ico_path:
            try:
                self.root.iconbitmap(self.ico_path)
            except Exception as e:
                logger.error(f"Erro ao carregar ícone principal: {str(e)}")
                self.try_convert_png_to_ico()
        else:
            self.try_convert_png_to_ico()
    
    def try_convert_png_to_ico(self):
        """Tenta converter um PNG para ICO se necessário"""
        png_path = self.find_png_icon()
        if png_path:
            try:
                from PIL import Image
                img = Image.open(png_path)
                with tempfile.NamedTemporaryFile(delete=False, suffix='.ico') as temp_ico:
                    img.save(temp_ico.name, format='ICO', sizes=[(16,16), (32,32), (48,48), (64,64)])
                    self.ico_path = temp_ico.name
                    self.root.iconbitmap(self.ico_path)
            except ImportError:
                logger.error("Pillow não instalado, não é possível converter PNG para ICO")
            except Exception as e:
                logger.error(f"Erro ao converter PNG para ICO: {str(e)}")
    
    def find_application_icon(self):
        """Localiza o ícone do aplicativo nos caminhos possíveis"""
        base_paths = []
        if getattr(sys, 'frozen', False):
            base_paths.append(sys._MEIPASS)
        base_paths.append(os.path.dirname(os.path.abspath(__file__)))
        base_paths.append(os.getcwd())
        
        icon_names = [
            "logoicogrupoprofarma.ico",
            "logo.ico",
            "icon.ico",
            "app_icon.ico"
        ]
        
        for base_path in base_paths:
            for icon_name in icon_names:
                candidate = os.path.join(base_path, icon_name)
                if os.path.exists(candidate):
                    return candidate
        return None

    def find_png_icon(self):
        """Localiza um ícone PNG para conversão"""
        base_paths = [
            os.path.dirname(os.path.abspath(__file__)),
            os.getcwd(),
            os.path.expanduser("~"),
            os.path.join(os.path.expanduser("~"), "Documents"),
            os.path.join(os.path.expanduser("~"), "Desktop"),
        ]
        
        icon_names = [
            "logoicogrupoprofarma.png",
            "logo.png",
            "icon.png"
        ]
        
        for base_path in base_paths:
            for icon_name in icon_names:
                candidate = os.path.join(base_path, icon_name)
                if os.path.exists(candidate):
                    return candidate
        return None

    def show_admin_dialog(self):
        top = tk.Toplevel(self.root)
        self.admin_dialog = top
        top.title("Configuração de Filtro Permanente")
        top.geometry("500x400")
        top.resizable(False, False)
        top.transient(self.root)
        top.grab_set()
        
        # Aplicar o ícone na janela de administrador
        if self.ico_path and os.path.exists(self.ico_path):
            try:
                top.iconbitmap(self.ico_path)
            except Exception as e:
                logger.error(f"Erro ao carregar ícone para admin: {str(e)}")
        else:
            self.try_convert_png_to_ico()
            if self.ico_path and os.path.exists(self.ico_path):
                try:
                    top.iconbitmap(self.ico_path)
                except Exception:
                    pass
        
        main_frame = ttk.Frame(top, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        type_frame = ttk.LabelFrame(main_frame, text="Tipo de Acesso")
        type_frame.pack(fill=tk.X, pady=(0, 10))
        admin_type_var = tk.StringVar(value="admin")
        admin_radio = ttk.Radiobutton(
            type_frame, 
            text="Administrador",
            variable=admin_type_var,
            value="admin"
        )
        admin_radio.pack(side=tk.LEFT, padx=5, pady=2)
        master_radio = ttk.Radiobutton(
            type_frame, 
            text="Administrador Master",
            variable=admin_type_var,
            value="master"
        )
        master_radio.pack(side=tk.LEFT, padx=5, pady=2)
        auth_frame = ttk.LabelFrame(main_frame, text="Autenticação")
        auth_frame.pack(fill=tk.X, pady=(0, 10))
        admin_pass_frame = ttk.Frame(auth_frame)
        admin_pass_frame.pack(fill=tk.X, pady=5)
        ttk.Label(admin_pass_frame, text="Senha:").pack(side=tk.LEFT, padx=(5,2))
        senha_var = tk.StringVar()
        senha_entry = ttk.Entry(admin_pass_frame, textvariable=senha_var, show="*", width=15)
        senha_entry.pack(side=tk.LEFT, padx=(0,5))
        senha_entry.focus_set()
        senha_entry.bind("<Return>", lambda event: check_password())
        
        def check_password():
            admin_type = admin_type_var.get()
            password = senha_var.get()
            if admin_type == "admin":
                stored_pass = self.admin_config.get('admin_password', 'admin')
                if stored_pass != 'admin' and re.match(r'^[A-Za-z0-9+/]+={0,2}$', stored_pass):
                    stored_pass = self.decrypt_data(stored_pass) or 'admin'
                if password == stored_pass:
                    auth_frame.pack_forget()
                    type_frame.pack_forget()
                    config_frame.pack(fill=tk.BOTH, expand=True)
                    top.geometry("500x400")
                else:
                    messagebox.showerror(
                        "Erro",
                        "Senha incorreta!",
                        parent=top
                    )
                    senha_entry.focus_set()
            elif admin_type == "master":
                stored_admin_pass = self.admin_config.get('admin_password', 'admin')
                if stored_admin_pass != 'admin' and re.match(r'^[A-Za-z0-9+/]+={0,2}$', stored_admin_pass):
                    stored_admin_pass = self.decrypt_data(stored_admin_pass) or 'admin'
                
                if password == stored_admin_pass:
                    auth_frame.pack_forget()
                    type_frame.pack_forget()
                    master_config_frame.pack(fill=tk.BOTH, expand=True)
                    top.geometry("500x400")
                else:
                    messagebox.showerror(
                        "Erro",
                        "Senha master incorreta!",
                        parent=top
                    )
                    senha_entry.focus_set()
        
        def forgot_password():
            config_path = os.path.abspath(self.admin_config_file)
            messagebox.showinfo(
                "Esqueci a senha",
                f"Para redefinir as senhas, exclua ou edite o arquivo de configuração:\n\n{config_path}\n\n" +
                "Após excluir, as senhas voltarão aos valores padrão (admin para administrador normal).",
                parent=self.root
            )
        
        auth_btn = ttk.Button(admin_pass_frame, text="Validar", 
                             command=check_password, width=8)
        auth_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(
            admin_pass_frame, 
            text="Esqueci a senha", 
            command=forgot_password,
            width=15
        ).pack(side=tk.LEFT, padx=5)
        config_frame = ttk.Frame(main_frame)
        users_frame = ttk.LabelFrame(config_frame, text="Usuários Bloqueados (um por linha)")
        users_frame.pack(fill=tk.X, pady=5)
        self.users_text = scrolledtext.ScrolledText(users_frame, height=5, font=('Consolas', 9))
        self.users_text.pack(fill=tk.X, padx=5, pady=5)
        self.users_text.insert(tk.END, "\n".join(self.permanent_filter['users']))
        commands_frame = ttk.LabelFrame(config_frame, text="Comandos Bloqueados (um por linha)")
        commands_frame.pack(fill=tk.X, pady=5)
        self.commands_text = scrolledtext.ScrolledText(commands_frame, height=5, font=('Consolas', 9))
        self.commands_text.pack(fill=tk.X, padx=5, pady=5)
        self.commands_text.insert(tk.END, "\n".join(self.permanent_filter['commands']))
        btn_frame = ttk.Frame(config_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        def save_admin_config():
            users = self.users_text.get("1.0", tk.END).splitlines()
            commands = self.commands_text.get("1.0", tk.END).splitlines()
            self.permanent_filter['users'] = [u.strip() for u in users if u.strip()]
            self.permanent_filter['commands'] = [c.strip() for c in commands if c.strip()]
            self.admin_config['permanent_filter_users'] = self.permanent_filter['users']
            self.admin_config['permanent_filter_commands'] = self.permanent_filter['commands']
            self.save_admin_config(self.admin_config)
            messagebox.showinfo("Sucesso", "Configuração salva com sucesso!", parent=top)
            top.destroy()
            if self.client:
                self.list_processes()
        
        save_btn = ttk.Button(btn_frame, text="Salvar Configuração", command=save_admin_config, style='Green.TButton')
        save_btn.pack(side=tk.LEFT, padx=5)
        cancel_btn = ttk.Button(btn_frame, text="Cancelar", command=top.destroy)
        cancel_btn.pack(side=tk.LEFT)
        master_config_frame = ttk.Frame(main_frame)
        url_frame = ttk.LabelFrame(master_config_frame, text="URL de Atualização")
        url_frame.pack(fill=tk.X, pady=5)
        ttk.Label(url_frame, text="Endpoint para verificar atualizações:").pack(anchor=tk.W, padx=5, pady=(2,0))
        update_url_var = tk.StringVar(value=self.admin_config.get('update_url', ""))
        update_url_entry = ttk.Entry(url_frame, textvariable=update_url_var, width=50)
        update_url_entry.pack(fill=tk.X, padx=5, pady=2)
        admin_pass_frame = ttk.LabelFrame(master_config_frame, text="Senha do Administrador")
        admin_pass_frame.pack(fill=tk.X, pady=5)
        ttk.Label(admin_pass_frame, text="Nova senha:").pack(side=tk.LEFT, padx=(5,2))
        new_admin_pass_var = tk.StringVar()
        new_admin_pass_entry = ttk.Entry(admin_pass_frame, textvariable=new_admin_pass_var, show="*", width=15)
        new_admin_pass_entry.pack(side=tk.LEFT, padx=(0,5))
        master_btn_frame = ttk.Frame(master_config_frame)
        master_btn_frame.pack(fill=tk.X, pady=10)
        
        def save_master_config():
            new_admin_pass = new_admin_pass_var.get().strip()
            if new_admin_pass:
                self.admin_config['admin_password'] = new_admin_pass
            self.admin_config['update_url'] = update_url_var.get().strip()
            if self.save_admin_config(self.admin_config):
                messagebox.showinfo(
                    "Sucesso", 
                    "Configuração master salva com sucesso!",
                    parent=top
                )
                top.destroy()
            else:
                messagebox.showerror("Erro", "Falha ao salvar configuração!", parent=top)
        
        save_btn = ttk.Button(master_btn_frame, text="Salvar Configuração", command=save_master_config, style='Green.TButton')
        save_btn.pack(side=tk.LEFT, padx=5)

        # NOVO BOTÃO: Gerar Executável
        generate_btn = ttk.Button(
            master_btn_frame, 
            text="Gerar Executável",
            command=self.generate_executable,
            width=15
        )
        generate_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = ttk.Button(master_btn_frame, text="Cancelar", command=top.destroy)
        cancel_btn.pack(side=tk.LEFT)
        top.update_idletasks()
        width = top.winfo_width()
        height = top.winfo_height()
        x = (top.winfo_screenwidth() // 2) - (width // 2)
        y = (top.winfo_screenheight() // 2) - (height // 2)
        top.geometry(f"{width}x{height}+{x}+{y}")

        def update_auth_ui(*args):
            if admin_type_var.get() == "admin":
                admin_pass_frame.pack(fill=tk.X, pady=5)
            else:
                admin_pass_frame.pack(fill=tk.X, pady=5)
        
        update_auth_ui()
        admin_type_var.trace_add("write", lambda *args: update_auth_ui())

    # NOVA FUNÇÃO: Gerar executável
    def generate_executable(self):
        """Gera um executável temporário e pergunta onde salvar"""
        try:
            # Verificar se está rodando como script Python
            if getattr(sys, 'frozen', False):
                messagebox.showinfo(
                    "Informação", 
                    "Você já está executando uma versão empacotada.",
                    parent=self.root
                )
                return
            
            # Criar um arquivo temporário
            temp_exe = tempfile.NamedTemporaryFile(
                suffix='.exe', 
                delete=False,
                prefix='SSHClient_'
            )
            temp_path = temp_exe.name
            temp_exe.close()
            
            # Atualizar status
            self.update_status("Gerando executável temporário...", "progress")
            
            # Comando para gerar o executável
            script_path = os.path.abspath(__file__)
            cmd = [
                sys.executable,
                "-m",
                "PyInstaller",
                "--onefile",
                "--windowed",
                "--name=SSHClient",
                f"--distpath={os.path.dirname(temp_path)}",
                f"--workpath={tempfile.gettempdir()}",
                f"--specpath={tempfile.gettempdir()}",
                script_path
            ]
            
            # Executar o comando
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                error_msg = f"Falha na geração: {stderr.decode(errors='ignore')}"
                logger.error(error_msg)
                messagebox.showerror(
                    "Erro", 
                    f"Falha ao gerar executável:\n{error_msg}",
                    parent=self.root
                )
                return
            
            # Perguntar onde salvar
            save_path = filedialog.asksaveasfilename(
                defaultextension=".exe",
                filetypes=[("Executável", "*.exe")],
                title="Salvar executável como"
            )
            
            if not save_path:
                os.unlink(temp_path)
                return
            
            # Mover o arquivo temporário para o destino
            shutil.move(temp_path, save_path)
            
            self.update_status(f"Executável gerado: {save_path}", "success")
            messagebox.showinfo(
                "Sucesso", 
                f"Executável gerado com sucesso em:\n{save_path}",
                parent=self.root
            )
            
        except Exception as e:
            logger.error(f"Erro ao gerar executável: {str(e)}")
            messagebox.showerror(
                "Erro", 
                f"Erro ao gerar executável:\n{str(e)}",
                parent=self.root
            )

    def is_caps_lock_on(self):
        if sys.platform.startswith('win'):
            hll_dll = ctypes.WinDLL("User32.dll")
            return hll_dll.GetKeyState(0x14) & 0xffff != 0
        return False

    def toggle_password_visibility(self):
        self.show_password = not self.show_password
        if self.show_password:
            self.password_entry.config(show="")
            self.eye_button.config(text="\U0001F512")  # Cadeado Unicode
        else:
            self.password_entry.config(show="*")
            self.eye_button.config(text="\U0001F441")  # Olho Unicode
        self.password_entry.focus_set()

    def on_password_focus_in(self, event):
        if self.is_caps_lock_on():
            messagebox.showwarning("Aviso", "CAPS LOCK está ativado!", parent=self.root)
            self.caps_lock_warning_shown = True
        else:
            self.caps_lock_warning_shown = False

    def on_password_key_release(self, event):
        if self.is_caps_lock_on() and not self.caps_lock_warning_shown:
            messagebox.showwarning("Aviso", "CAPS LOCK está ativado!", parent=self.root)
            self.caps_lock_warning_shown = True
        elif not self.is_caps_lock_on():
            self.caps_lock_warning_shown = False

    def safe_close(self):
        if not self.running:  # Já está fechando?
            return
            
        self.running = False
        self.disconnect()
        if self.temp_ico_file and os.path.exists(self.temp_ico_file):
            try:
                os.unlink(self.temp_ico_file)
            except Exception:
                pass
        self.root.destroy()
        # Forçar encerramento do processo para evitar múltiplas instâncias
        if IS_EXE:
            os._exit(0)

    def show_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Ajuda - Instruções de Uso")
        help_window.geometry("900x650")
        help_window.resizable(True, True)
        help_window.transient(self.root)
        help_window.grab_set()
        main_frame = ttk.Frame(help_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        instructions = (
            "MANUAL COMPLETO DO GERENCIADOR SSH AVANÇADO v1.2.13\n\n"
            "1. CONEXÃO SSH\n"
            "   - Preencha os campos de Host, Usuário, Senha e Porta\n"
            "   - Clique em 'Conectar' ou pressione Enter no campo de senha\n"
            "   - Histórico de hosts é mantido automaticamente\n"
            "   - Para desconectar: botão 'Desconectar'\n\n"
            "2. ABA 'DERRUBAR CONF'\n"
            "   - Lista todos os processos ativos do servidor\n"
            "   - Filtros automáticos bloqueiam usuários críticos (root, zabbix, etc)\n"
            "   - Filtros adicionais por usuário, PID ou comando\n"
            "   - Selecione PIDs para derrubar:\n"
            "        * Clique em um PID para selecionar\n"
            "        * Ctrl+Clique para selecionar múltiplos PIDs\n"
            "        * Shift+Clique para seleção contígua\n"
            "        * Ctrl+A para selecionar todos\n"
            "        * Clique no cabeçalho para ordenar coluna\n"
            "   - Derrubar usando menu interativo do sistema\n\n"
            "3. ABA 'DERRUBAR MATRÍCULA E ROMANEIO'\n"
            "   - Consulta processos relacionados a matrículas ou romaneios\n"
            "   - Busca em /d/work por arquivos com o padrão especificado\n"
            "   - Resultados mostrados em tabela com usuário, PID e nome\n"
            "   - Selecione PIDs na tabela para derrubar\n\n"
            "4. ABA 'CONSULTAR TELA'\n"
            "   - Consulta processos por número de tela\n"
            "   - Busca em /d/dados por arquivos com o padrão especificado\n"
            "   - Use '*' para listar todas as telas\n"
            "   - Mesma mecânica de seleção de PIDs das outras abas\n\n"
            "5. ABA 'TERMINAL INTERATIVO'\n"
            "   - Sessão SSH interativa em tempo real\n"
            "   - Execute comandos diretamente no servidor\n"
            "   - Saída exibida continuamente\n"
            "   - Use 'exit' para sair da sessão\n\n"
            "6. ABA 'EXECUTAR COMANDOS'\n"
            "   - Execute múltiplos comandos de uma vez\n"
            "   - Cada comando deve estar em uma linha separada\n"
            "   - Resultados exibidos na área abaixo\n\n"
            "7. ADMINISTRAÇÃO\n"
            "   - Botão 'Administrador' no canto superior direito\n"
            "   - Duas opções de acesso:\n"
            "        * Administrador: Gerencia filtros permanentes\n"
            "        * Administrador Master: Configura senhas e URL de atualização\n"
            "   - Senha padrão para administrador normal: 'admin'\n"
            "   - Filtros permanentes padrão:\n"
            "        Usuários bloqueados: root, zabbix, sshd, postfix, nscd, message+, usertra+, prod, fatura, logist, lp\n"
            "        Comandos bloqueados: (sd-pam), -bash, /opt/microfocu, /opt/microfocus, /usr/lib/system, bash, pg /d/work/est2, ps aux, sh /app/scripts, sh /usr/bin/cha, /usr/lib/ssh/sf\n\n"
            "8. SEGURANÇA\n"
            "   - Host keys são verificadas e armazenadas\n"
            "   - Senhas administrativas são criptografadas\n"
            "   - Conexões usam protocolo SSH seguro\n\n"
            "CONTATO E SUPORTE:\n"
            "   WhatsApp: 31 99363-9500\n"
            "   LinkedIn: https://www.linkedin.com/in/franklintadeu/\n\n"
            "VERSÃO ATUAL: " + SOFTWARE_VERSION
        )
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        text_area = scrolledtext.ScrolledText(
            text_frame, 
            wrap=tk.WORD,
            font=('Segoe UI', 10),
            padx=10,
            pady=10
        )
        text_area.pack(fill=tk.BOTH, expand=True)
        text_area.insert(tk.INSERT, instructions)
        text_area.configure(state=tk.DISABLED)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10,0))
        close_btn = ttk.Button(
            btn_frame, 
            text="Fechar", 
            command=help_window.destroy,
            width=10
        )
        close_btn.pack()
        self.center_window(help_window)

    def center_window(self, window):
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        window.geometry(f"+{x}+{y}")

    def load_host_history(self):
        history = []
        config_path = os.path.expanduser("~/.ssh_tool_history")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    history = [line.strip() for line in f.readlines()]
            except Exception:
                pass
        return list(set(history))

    def save_host_history(self, host):
        if host not in self.host_history:
            self.host_history.append(host)
        config_path = os.path.expanduser("~/.ssh_tool_history")
        try:
            with open(config_path, 'w') as f:
                f.write("\n".join(self.host_history))
        except Exception:
            pass
        self.host_combo['values'] = self.host_history

    def on_host_selected(self, event=None):
        new_host = self.host_var.get()
        if self.client and self.current_host != new_host:
            self.disconnect()

    def treeview_sort_column(self, tv, col, reverse):
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        try:
            if col in ('pid', 'idle'):
                l.sort(key=lambda t: float(t[0]) if t[0].strip() else 0.0, reverse=reverse)
            else:
                l.sort(key=lambda t: t[0].lower(), reverse=reverse)
        except ValueError:
            l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)
        tv.heading(col, command=lambda: self.treeview_sort_column(tv, col, not reverse))

    def on_pid_select(self, event):
        selected_pids = []
        for item in self.process_tree.selection():
            pid = self.process_tree.item(item, 'values')[1]
            selected_pids.append(pid)
        self.pids_var.set(" ".join(selected_pids))
    
    def on_matricula_pid_select(self, event):
        selected_pids = []
        for item in self.result_tree.selection():
            values = self.result_tree.item(item, 'values')
            if len(values) >= 2:
                pid = values[1]
                selected_pids.append(pid)
        self.matricula_pids_var.set(" ".join(selected_pids))
    
    def on_tela_pid_select(self, event):
        selected_pids = []
        for item in self.tela_tree.selection():
            values = self.tela_tree.item(item, 'values')
            if len(values) >= 2:
                pid = values[1]
                selected_pids.append(pid)
        self.tela_pids_var.set(" ".join(selected_pids))

    def apply_filters(self):
        user_filter = self.user_filter_var.get().lower().strip()
        pid_filter = self.pid_filter_var.get().strip()
        cmd_filter = self.cmd_filter_var.get().lower().strip()
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        for proc in self.all_processes:
            user_match = not user_filter or user_filter in proc['user'].lower()
            pid_match = not pid_filter or pid_filter in proc['pid']
            cmd_match = not cmd_filter or cmd_filter in proc['command'].lower()
            if user_match and pid_match and cmd_match:
                self.add_process_to_tree(proc)

    def clear_filters(self):
        self.user_filter_var.set("")
        self.pid_filter_var.set("")
        self.cmd_filter_var.set("")
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        for proc in self.all_processes:
            self.add_process_to_tree(proc)

    def append_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        if self.capturing_matricula:
            self.matricula_output += text
        if self.capturing_tela:
            self.tela_output += text

    def append_result(self, text):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

    def connect(self):
        new_host = self.host_var.get()
        if self.client and self.current_host != new_host:
            self.disconnect()
        host = new_host
        user = self.user_var.get()
        password = self.password_var.get()
        try:
            port = int(self.port_var.get())
        except ValueError:
            port = 22
        self.client = self.create_ssh_client(host, user, password, port)
        if self.client:
            self.current_host = host
            self.start_interactive_shell()
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.update_status(f"Conectado a {host}", "success")
            self.list_processes()

    def disconnect(self):
        if self.client:
            try:
                self.stop_interactive_session()
                self.client.close()
            except Exception as e:
                logger.error(f"Erro ao desconectar: {str(e)}")
            finally:
                self.client = None
                self.current_host = None
                self.connect_btn.config(state=tk.NORMAL)
                self.disconnect_btn.config(state=tk.DISABLED)
                self.output_text.config(state=tk.NORMAL)
                self.output_text.insert(tk.END, "\n--- Conexão encerrada ---\n")
                self.output_text.config(state=tk.DISABLED)
                self.update_status("Desconectado")
        else:
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.update_status("Desconectado")

    def create_ssh_client(self, host, user, password, port=22):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(InteractiveHostKeyPolicy(self.root, port))
        try:
            client.load_system_host_keys()
        except Exception:
            logger.warning("Não foi possível carregar host keys do sistema")
        try:
            client.connect(
                hostname=host,
                username=user,
                password=password,
                port=port,
                timeout=10,
                banner_timeout=20
            )
            self.save_host_history(host)
            return client
        except paramiko.AuthenticationException:
            self.update_status("Falha na autenticação", "error")
            messagebox.showerror("Erro", "Autenticação falhou. Verifique suas credenciais.")
            self.host_combo.focus_set()
        except paramiko.SSHException as e:
            self.update_status(f"Erro SSH: {str(e)}", "error")
            messagebox.showerror("Erro", f"Erro na conexão SSH: {str(e)}")
            self.host_combo.focus_set()
        except Exception as e:
            self.update_status(f"Erro inesperado: {str(e)}", "error")
            messagebox.showerror("Erro", f"Erro inesperado: {str(e)}")
            self.host_combo.focus_set()
        self.root.after(100, lambda: self.connect_btn.config(state=tk.NORMAL))
        return None

    def start_interactive_shell(self):
        if not self.client:
            self.update_status("Não conectado", "error")
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
        try:
            self.shell = self.client.invoke_shell()
            self.stop_receiver.clear()
            # Iniciar thread para receber a saída
            self.receiver_thread = threading.Thread(target=self.receive_output, daemon=True)
            self.receiver_thread.start()
        except Exception as e:
            self.update_status(f"Erro ao iniciar sessão: {str(e)}", "error")
            messagebox.showerror("Erro", f"Erro ao iniciar sessão: {str(e)}")
            self.host_combo.focus_set()
            self.disconnect()

    def receive_output(self):
        while self.running and not self.stop_receiver.is_set() and self.shell:
            try:
                if self.shell.recv_ready():
                    data = self.shell.recv(4096).decode(errors='ignore')
                    if data:
                        self.root.after(0, self.append_output, data)
                else:
                    time.sleep(0.1)
            except Exception as e:
                if self.running:
                    logger.error(f"Erro na recepção: {str(e)}")
                    self.root.after(0, self.disconnect)
                break

    def send_command(self, event=None):
        command = self.cmd_var.get().strip()
        if not command:
            return
        if not self.shell:
            self.update_status("Sessão interativa não está ativa!", "error")
            messagebox.showerror("Erro", "Sessão interativa não está ativa!")
            self.host_combo.focus_set()
            return
        if command.lower() in ['exit', 'quit']:
            self.stop_interactive_session()
            return
        try:
            self.shell.send(command + "\n")
            self.cmd_var.set("")
        except Exception as e:
            self.update_status(f"Erro ao enviar comando: {str(e)}", "error")
            messagebox.showerror("Erro", f"Erro ao enviar comando: {str(e)}")
            self.host_combo.focus_set()
            self.disconnect()

    def stop_interactive_session(self):
        if self.shell:
            try:
                self.shell.send("exit\n")
                time.sleep(0.5)
                self.shell.close()
            except Exception:
                pass
        self.stop_receiver.set()
        self.shell = None
        self.append_output("\nSessão encerrada.\n")

    def execute_commands(self):
        if not self.client:
            self.update_status("Não conectado", "error")
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
        commands = self.commands_text.get("1.0", tk.END).splitlines()
        if not commands:
            return
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state=tk.DISABLED)
        threading.Thread(
            target=self._execute_commands, 
            args=(commands,),
            daemon=True
        ).start()

    def _execute_commands(self, commands):
        try:
            for cmd in commands:
                if not cmd.strip() or not self.running:
                    continue
                _, stdout, stderr = self.client.exec_command(cmd, timeout=30)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode(errors='ignore').strip()
                error = stderr.read().decode(errors='ignore').strip()
                result = f"\n$ {cmd}\n"
                if output:
                    result += output + "\n"
                if error:
                    result += f"ERRO: {error}\n"
                if exit_status != 0:
                    result += f"Comando falhou com status: {exit_status}\n"
                self.root.after(0, self.append_result, result)
        except paramiko.SSHException as e:
            self.root.after(0, self.update_status, f"Falha na execução: {str(e)}", "error")
            self.root.after(0, self.matricula_status_var.set, 
                          f"Erro na operação: {str(e)}")
            self.root.after(0, messagebox.showerror, "Erro", f"Falha na execução: {str(e)}")
            self.root.after(0, self.disconnect)
        except Exception as e:
            self.root.after(0, self.update_status, f"Erro inesperado: {str(e)}", "error")
            self.root.after(0, self.matricula_status_var.set, 
                          f"Erro na operação: {str(e)}")
            self.root.after(0, messagebox.showerror, "Erro", f"Erro inesperado: {str(e)}")
            self.root.after(0, self.disconnect)

    def list_processes(self):
        if not self.client:
            self.update_status("Não conectado", "error")
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        threading.Thread(target=self._list_processes, daemon=True).start()

    def _list_processes(self):
        try:
            cmd = "ps aux"
            _, stdout, stderr = self.client.exec_command(cmd, timeout=30)
            output = stdout.read().decode(errors='ignore').strip()
            error = stderr.read().decode(errors='ignore').strip()
            if error:
                self.root.after(0, self.update_status, f"Erro ao listar processos: {error}", "error")
                self.root.after(0, messagebox.showerror, "Erro", f"Erro ao listar processos: {error}")
                return
            processes = []
            for line in output.split('\n')[1:]:
                if line.strip():
                    parts = line.split(maxsplit=10)
                    if len(parts) >= 11:
                        user = parts[0]
                        pid = parts[1]
                        command = parts[10]
                        skip = False
                        # Filtrar usuários
                        for blocked_user in self.permanent_filter['users']:
                            if user.lower() == blocked_user.lower():
                                skip = True
                                break
                        # Filtrar comandos
                        if not skip:
                            for blocked_cmd in self.permanent_filter['commands']:
                                if blocked_cmd.lower() in command.lower():
                                    skip = True
                                    break
                        if not skip:
                            processes.append({
                                'user': user,
                                'pid': pid,
                                'idle': parts[9],
                                'command': command
                            })
            self.all_processes = processes
            for proc in self.all_processes:
                self.root.after(0, self.add_process_to_tree, proc)
        except Exception as e:
            self.root.after(0, self.update_status, f"Falha ao listar processos: {str(e)}", "error")
            self.root.after(0, messagebox.showerror, "Erro", f"Falha ao listar processos: {str(e)}")
            self.root.after(0, self.disconnect)
    
    def add_process_to_tree(self, proc):
        self.process_tree.insert('', tk.END, values=(
            proc['user'], 
            proc['pid'], 
            proc['idle'], 
            proc['command']
        ))

    def kill_pids(self):
        if not self.client:
            self.update_status("Não conectado", "error")
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
        pids_input = self.pids_var.get().strip()
        if not pids_input:
            self.update_status("Nenhum PID especificado", "warning")
            messagebox.showwarning("Aviso", "Nenhum PID especificado!")
            return
        pids = []
        for part in re.split(r'[,\s\-]+', pids_input):
            if part.strip():
                pids.append(part.strip())
        if not pids:
            self.update_status("Nenhum PID válido encontrado", "warning")
            messagebox.showwarning("Aviso", "Nenhum PID válido encontrado!")
            return
        confirm_message = (
            f"Tem certeza que deseja derrubar {len(pids)} processo(s)?\n\n"
            f"PIDs: {', '.join(pids)}\n\n"
            "Esta operação usará o menu interativo do sistema."
        )
        confirm = messagebox.askyesno("Confirmar Operação", confirm_message)
        if not confirm:
            return
        if not self.shell:
            self.update_status("Sessão interativa não está ativa!", "error")
            messagebox.showerror("Erro", "Sessão interativa não está ativa!")
            self.host_combo.focus_set()
            return
        threading.Thread(
            target=self._kill_pids_interactive, 
            args=(pids,),
            daemon=True
        ).start()

    def _kill_pids_interactive(self, pids):
        try:
            pids_str = " ".join(pids)
            sequence = [
                "3",
                pids_str,
                ""
            ]
            for cmd in sequence:
                if not self.running:
                    return
                self.root.after(0, self.append_output, f">>> Enviando: {cmd}\n")
                self.shell.send(cmd + "\n")
                time.sleep(0.5)
            self.root.after(0, self.append_output, "\nComandos enviados. Verifique o terminal.\n")
            self.root.after(0, self.update_status, f"{len(pids)} processos derrubados", "success")
        except Exception as e:
            self.root.after(0, self.update_status, f"Erro ao derrubar processos: {str(e)}", "error")
            self.root.after(0, messagebox.showerror, "Erro", f"Erro ao derrubar processos: {str(e)}")
            self.root.after(0, self.disconnect)
    
    def consultar_matricula(self):
        if not self.client:
            self.update_status("Não conectado", "error")
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
        matricula = self.matricula_var.get().strip()
        if not matricula:
            matricula = ""
        self.matricula_status_var.set(f"Consultando matrícula/romaneio {matricula}...")
        self.clear_matricula_results()
        self.matricula_pids_var.set("")
        self.capturing_matricula = True
        self.matricula_output = ""
        threading.Thread(
            target=self._consultar_matricula, 
            args=(matricula,),
            daemon=True
        ).start()

    def _consultar_matricula(self, matricula):
        try:
            sequence = [
                "2",
                "/d/work",
                f"*{matricula}",
                ""
            ]
            for cmd in sequence:
                if not self.running:
                    return
                self.root.after(0, self.append_output, f">>> Enviando: {cmd}\n")
                self.shell.send(cmd + "\n")
                time.sleep(1)
            time.sleep(2)
            self.capturing_matricula = False
            self.root.after(0, self.process_matricula_output, matricula)
        except Exception as e:
            self.capturing_matricula = False
            self.root.after(0, self.update_status, f"Erro ao consultar matrícula: {str(e)}", "error")
            self.root.after(0, self.matricula_status_var.set, 
                          f"Erro na operação: {str(e)}")
            self.root.after(0, messagebox.showerror, "Erro", f"Erro ao consultar matrícula: {str(e)}")
            self.root.after(0, self.disconnect)

    def clear_matricula_results(self):
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)

    def process_matricula_output(self, matricula):
        try:
            pattern = r'^(\S+)\s+(\d+)\s+(\S.*)$'
            matches = re.findall(pattern, self.matricula_output, re.MULTILINE)
            if not matches:
                self.matricula_status_var.set(f"Nenhum processo encontrado para {matricula}")
                self.update_status(f"Nenhum processo encontrado para {matricula}", "warning")
                return
            for match in matches:
                self.result_tree.insert('', tk.END, values=match)
            self.matricula_status_var.set(f"Consulta concluída: {len(matches)} processos encontrados")
            self.update_status(f"{len(matches)} processos encontrados para {matricula}", "success")
        except Exception as e:
            self.matricula_status_var.set(f"Erro ao processar resultados: {str(e)}")
            self.update_status(f"Erro ao processar resultados: {str(e)}", "error")
    
    def derrubar_pid_selecionado(self):
        if not self.client:
            self.update_status("Não conectado", "error")
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
        selected_items = self.result_tree.selection()
        if not selected_items:
            self.update_status("Nenhum PID selecionado", "warning")
            messagebox.showwarning("Aviso", "Nenhum PID selecionado na tabela!")
            return
        pids = []
        for item in selected_items:
            values = self.result_tree.item(item, 'values')
            if len(values) >= 2:
                pid = values[1]
                pids.append(pid)
        if not pids:
            self.update_status("Nenhum PID válido selecionado", "warning")
            messagebox.showwarning("Aviso", "Nenhum PID válido selecionado!")
            return
        confirm_message = (
            f"Tem certeza que deseja derrubar {len(pids)} processo(s)?\n\n"
            f"PIDs: {', '.join(pids)}\n\n"
            "Esta operação usará o menu interativo do sistema."
        )
        confirm = messagebox.askyesno("Confirmar Operação", confirm_message)
        if not confirm:
            return
        if not self.shell:
            self.update_status("Sessão interativa não está ativa!", "error")
            messagebox.showerror("Erro", "Sessão interativa não está ativa!")
            self.host_combo.focus_set()
            return
        threading.Thread(
            target=self._kill_pids_interactive, 
            args=(pids,),
            daemon=True
        ).start()
    
    def consultar_tela(self):
        if not self.client:
            self.update_status("Não conectado", "error")
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
        tela = self.tela_var.get().strip()
        if not tela:
            tela = "*"
        self.tela_status_var.set(f"Consultando tela {tela}...")
        self.clear_tela_results()
        self.tela_pids_var.set("")
        self.capturing_tela = True
        self.tela_output = ""
        threading.Thread(
            target=self._consultar_tela, 
            args=(tela,),
            daemon=True
        ).start()

    def _consultar_tela(self, tela):
        try:
            sequence = [
                "2",
                "/d/dados",
                f"*{tela}",
                ""
            ]
            for cmd in sequence:
                if not self.running:
                    return
                self.root.after(0, self.append_output, f">>> Enviando: {cmd}\n")
                self.shell.send(cmd + "\n")
                time.sleep(1)
            time.sleep(2)
            self.capturing_tela = False
            self.root.after(0, self.process_tela_output, tela)
        except Exception as e:
            self.capturing_tela = False
            self.root.after(0, self.update_status, f"Erro ao consultar tela: {str(e)}", "error")
            self.root.after(0, self.tela_status_var.set, 
                          f"Erro na operação: {str(e)}")
            self.root.after(0, messagebox.showerror, "Erro", f"Erro ao consultar tela: {str(e)}")
            self.root.after(0, self.disconnect)

    def clear_tela_results(self):
        for item in self.tela_tree.get_children():
            self.tela_tree.delete(item)

    def process_tela_output(self, tela):
        try:
            pattern = r'^(\S+)\s+(\d+)\s+(\S.*)$'
            matches = re.findall(pattern, self.tela_output, re.MULTILINE)
            if not matches:
                self.tela_status_var.set(f"Nenhum processo encontrado para {tela}")
                self.update_status(f"Nenhum processo encontrado para {tela}", "warning")
                return
            for match in matches:
                self.tela_tree.insert('', tk.END, values=match)
            self.tela_status_var.set(f"Consulta concluída: {len(matches)} processos encontrados")
            self.update_status(f"{len(matches)} telas encontradas para {tela}", "success")
        except Exception as e:
            self.tela_status_var.set(f"Erro ao processar resultados: {str(e)}")
            self.update_status(f"Erro ao processar resultados: {str(e)}", "error")
    
    def derrubar_pid_tela(self):
        if not self.client:
            self.update_status("Não conectado", "error")
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
        selected_items = self.tela_tree.selection()
        if not selected_items:
            self.update_status("Nenhum PID selecionado", "warning")
            messagebox.showwarning("Aviso", "Nenhum PID selecionado na tabela!")
            return
        pids = []
        for item in selected_items:
            values = self.tela_tree.item(item, 'values')
            if len(values) >= 2:
                pid = values[1]
                pids.append(pid)
        if not pids:
            self.update_status("Nenhum PID válido selecionado", "warning")
            messagebox.showwarning("Aviso", "Nenhum PID válido selecionado!")
            return
        confirm_message = (
            f"Tem certeza que deseja derrubar {len(pids)} processo(s)?\n\n"
            f"PIDs: {', '.join(pids)}\n\n"
            "Esta operação usará o menu interativo do sistema."
        )
        confirm = messagebox.askyesno("Confirmar Operação", confirm_message)
        if not confirm:
            return
        if not self.shell:
            self.update_status("Sessão interativa não está ativa!", "error")
            messagebox.showerror("Erro", "Sessão interativa não está ativa!")
            self.host_combo.focus_set()
            return
        threading.Thread(
            target=self._kill_pids_interactive, 
            args=(pids,),
            daemon=True
        ).start()

# Inicialização da aplicação
if __name__ == "__main__":
    root = tk.Tk()
    app = SSHClientGUI(root)
    root.mainloop()