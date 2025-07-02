import os
import sys
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
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
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag

# Verificar se está rodando como executável empacotado (exe)
IS_EXE = getattr(sys, 'frozen', False)

# Versão do software - importante para atualizações
SOFTWARE_VERSION = "1.2.6"  # Corrigido problema do ícone

# Oculta o console ao iniciar o .exe (Windows apenas)
if sys.platform.startswith('win') and IS_EXE:
    console_handle = ctypes.windll.kernel32.GetConsoleWindow()
    if console_handle:
        ctypes.windll.user32.ShowWindow(console_handle, 0)

# Configuração básica de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ssh_tool')

# FILTROS PERMANENTES ATUALIZADOS CONFORME SOLICITADO
PERMANENT_FILTER_USERS = ['root', 'zabbix', 'sshd', 'postfix', 'nscd', 'message+', 'usertra+', 'prod', 'fatura', 'logist', 'lp']
PERMANENT_FILTER_COMMANDS = [
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
    '/usr/lib/ssh/sf'
]

class InteractiveHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Política interativa para verificação de host keys com opção de lembrar permanentemente"""
    def __init__(self, root, port=22):
        self.root = root
        self.port = port
        super().__init__()
    
    def missing_host_key(self, client, hostname, key):
        """Trata chaves de host desconhecidas mostrando diálogo de confirmação"""
        # Gerar fingerprint SHA256 em formato base64
        fp = hashlib.sha256(key.asbytes()).digest()
        fp_base64 = base64.b64encode(fp).rstrip(b'=').decode('ascii')
        
        # Criar janela de diálogo personalizada
        top = tk.Toplevel(self.root)
        top.title("Verificação de Segurança")
        top.geometry("600x250")
        top.resizable(False, False)
        top.transient(self.root)
        top.grab_set()
        
        # Frame principal
        frame = ttk.Frame(top, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Mensagem de alerta
        msg = (
            f"ATENÇÃO: Host desconhecido '{hostname}'!\n\n"
            f"Fingerprint (SHA256): {fp_base64}\n\n"
            "Deseja confiar neste host?"
        )
        ttk.Label(frame, text=msg).pack(pady=10)
        
        # Checkbox para lembrar host permanentemente
        self.remember_var = tk.BooleanVar(value=True)
        save_check = ttk.Checkbutton(
            frame, 
            text="Lembrar este host permanentemente",
            variable=self.remember_var
        )
        save_check.pack(pady=5)
        
        # Função para lidar com a resposta do usuário
        user_response = None
        
        def handle_response(response):
            nonlocal user_response
            user_response = response
            top.destroy()
        
        # Frame para botões
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Sim", command=lambda: handle_response(True)).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Não", command=lambda: handle_response(False)).pack(side=tk.LEFT, padx=10)
        
        # Centralizar a janela
        top.update_idletasks()
        width = top.winfo_width()
        height = top.winfo_height()
        x = (top.winfo_screenwidth() // 2) - (width // 2)
        y = (top.winfo_screenheight() // 2) - (height // 2)
        top.geometry(f"{width}x{height}+{x}+{y}")
        
        # Esperar pela resposta do usuário
        self.root.wait_window(top)
        
        if not user_response:
            raise paramiko.SSHException(f"Host {hostname} rejeitado pelo usuário")
        
        # Adicionar a chave à sessão atual
        client._host_keys.add(hostname, key.get_name(), key)
        
        # Se o usuário escolheu lembrar permanentemente
        if self.remember_var.get():
            try:
                # Obter o caminho do arquivo known_hosts
                known_hosts = os.path.expanduser("~/.ssh/known_hosts")
                
                # Criar diretório se não existir
                os.makedirs(os.path.dirname(known_hosts), exist_ok=True)
                
                # Formatar hostname corretamente para portas não padrão
                if self.port != 22:
                    host_key = f"[{hostname}]:{self.port}"
                else:
                    host_key = hostname
                
                # Adicionar a chave ao arquivo known_hosts
                with open(known_hosts, 'a') as f:
                    f.write(f"{host_key} {key.get_name()} {key.get_base64()}\n")
                
                messagebox.showinfo("Sucesso", 
                    f"Host {host_key} adicionado permanentemente ao arquivo known_hosts")
            except Exception as e:
                messagebox.showerror("Erro", 
                    f"Falha ao salvar no known_hosts: {str(e)}")

class SSHClientGUI:
    """Interface gráfica para cliente SSH com múltiplas funcionalidades"""
    def __init__(self, root):
        self.root = root
        self.root.title(f"Gerenciador SSH Avançado v{SOFTWARE_VERSION}")
        
        # Tamanho inicial aumentado para melhor visualização
        self.root.geometry("950x600")
        
        # Configuração de expansão para a janela principal
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        # Variáveis para armazenar a referência da imagem do logo
        self.logo_photo = None
        self.temp_ico_file = None
        
        # Tenta carregar o ícone
        self.load_application_icon()
        
        # Cache de processos
        self.all_processes = []
        
        # Histórico de hosts
        self.host_history = []
        
        # Configuração de senha e URL de atualização
        self.admin_config_file = os.path.join(os.path.expanduser("~"), ".ssh_tool_config")
        
        # CORREÇÃO: DEFINIR CONSTANTES PRIMEIRO
        self.DEFAULT_UPDATE_URL = "https://raw.githubusercontent.com/seu-usuario/seu-repositorio/main/version.json"
        
        # Agora carregar a configuração
        self.admin_config = self.load_admin_config()
        
        # Filtro permanente (interno, não visível) - USANDO VALORES FIXOS DO CÓDIGO
        self.permanent_filter = {
            'users': PERMANENT_FILTER_USERS,
            'commands': PERMANENT_FILTER_COMMANDS
        }
        
        # Configurar estilo visual moderno
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # ALTERAÇÃO SOLICITADA: NOVAS CORES PARA AS ABAS
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
        
        # Frame principal para organização
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Variáveis de estado
        self.client = None
        self.shell = None
        self.current_host = None
        self.stop_receiver = threading.Event()
        self.receiver_thread = None
        self.running = True  # Flag para controlar threads
        self.show_password = False  # Estado da visibilidade da senha
        self.caps_lock_warning_shown = False  # Controle de aviso de Caps Lock
        
        # Frame de conexão com layout aprimorado
        conn_frame = ttk.LabelFrame(main_frame, text="Configuração de Conexão")
        conn_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Grid para campos de conexão
        ttk.Label(conn_frame, text="Host:").grid(row=0, column=0, padx=3, pady=2, sticky=tk.W)
        self.host_var = tk.StringVar(value="mg01.grp.local")
        self.host_combo = ttk.Combobox(conn_frame, textvariable=self.host_var, width=15)
        self.host_combo.grid(row=0, column=1, padx=3, pady=2, sticky=tk.W)
        self.host_combo['values'] = self.load_host_history()
        self.host_combo.bind("<<ComboboxSelected>>", self.on_host_selected)
        # Adicionar evento Enter para conectar
        self.host_combo.bind("<Return>", lambda event: self.connect())
        
        ttk.Label(conn_frame, text="Usuário:").grid(row=0, column=2, padx=(8,3), pady=2, sticky=tk.W)
        self.user_var = tk.StringVar(value="prod")
        user_entry = ttk.Entry(conn_frame, textvariable=self.user_var, width=10)
        user_entry.grid(row=0, column=3, padx=3, pady=2, sticky=tk.W)
        # Adicionar evento Enter para conectar
        user_entry.bind("<Return>", lambda event: self.connect())
        
        ttk.Label(conn_frame, text="Senha:").grid(row=0, column=4, padx=(8,3), pady=2, sticky=tk.W)
        
        # Frame para senha e botão de olho
        password_frame = ttk.Frame(conn_frame)
        password_frame.grid(row=0, column=5, padx=3, pady=2, sticky=tk.W)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=10)
        self.password_entry.pack(side=tk.LEFT)
        self.password_entry.bind("<Return>", lambda event: self.connect())
        
        # Botão de olho para mostrar/ocultar senha
        self.eye_button = ttk.Button(
            password_frame, 
            text="👁", 
            width=2, 
            command=self.toggle_password_visibility
        )
        self.eye_button.pack(side=tk.LEFT, padx=(2,0))
        
        # Verificar Caps Lock ao ganhar foco
        self.password_entry.bind("<FocusIn>", self.on_password_focus_in)
        self.password_entry.bind("<KeyRelease>", self.on_password_key_release)
        
        ttk.Label(conn_frame, text="Porta:").grid(row=0, column=6, padx=(8,3), pady=2, sticky=tk.W)
        self.port_var = tk.StringVar(value="22")
        port_entry = ttk.Entry(conn_frame, textvariable=self.port_var, width=4)
        port_entry.grid(row=0, column=7, padx=3, pady=2, sticky=tk.W)
        # Adicionar evento Enter para conectar
        port_entry.bind("<Return>", lambda event: self.connect())
        
        # Frame para botões de conexão
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.grid(row=0, column=8, padx=(10,3), pady=2, sticky=tk.E)
        
        self.connect_btn = ttk.Button(btn_frame, text="Conectar", 
                                     command=self.connect, style='Green.TButton', width=9)
        self.connect_btn.pack(side=tk.LEFT, padx=2)
        
        self.disconnect_btn = ttk.Button(btn_frame, text="Desconectar", 
                                        command=self.disconnect, state=tk.DISABLED,
                                        style='Red.TButton', width=10)
        self.disconnect_btn.pack(side=tk.LEFT, padx=2)
        
        # Botão Administração
        self.admin_btn = ttk.Button(
            btn_frame, 
            text="Administrador",
            command=self.show_admin_dialog,
            style='Blue.TButton',
            width=14
        )
        self.admin_btn.pack(side=tk.LEFT, padx=2)
        
        # Botão Ajuda
        help_btn = ttk.Button(
            btn_frame, 
            text="Ajuda?",
            command=self.show_help,
            width=6
        )
        help_btn.pack(side=tk.LEFT, padx=2)
        
        # Notebook (abas) com padding
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # ===== ABA DERRUBAR CONF (PRIMEIRA ABA) =====
        pid_frame = ttk.Frame(self.notebook)
        self.notebook.add(pid_frame, text=" Derrubar Conf ")
        
        # Frame de controle superior
        top_frame = ttk.Frame(pid_frame)
        top_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # Frame para botões de ação
        action_frame = ttk.Frame(top_frame)
        action_frame.pack(side=tk.LEFT, padx=(0,5))
        
        list_btn = ttk.Button(action_frame, text="Listar Processos", 
                  command=self.list_processes, width=15)
        list_btn.pack(side=tk.TOP, pady=1)
        refresh_btn = ttk.Button(action_frame, text="Atualizar Lista", 
                  command=self.list_processes, width=15)
        refresh_btn.pack(side=tk.TOP, pady=1)
        
        # Frame para filtros voláteis (visíveis)
        filter_frame = ttk.LabelFrame(top_frame, text="Filtros")
        filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=0)
        
        # Filtro por usuário (volátil)
        ttk.Label(filter_frame, text="Usuário:").pack(side=tk.LEFT, padx=(5,2))
        self.user_filter_var = tk.StringVar()
        user_filter_entry = ttk.Entry(filter_frame, textvariable=self.user_filter_var, width=10)
        user_filter_entry.pack(side=tk.LEFT, padx=(0,3))
        user_filter_entry.bind("<Return>", lambda event: self.apply_filters())
        
        # Filtro por PID (volátil)
        ttk.Label(filter_frame, text="PID:").pack(side=tk.LEFT, padx=(5,2))
        self.pid_filter_var = tk.StringVar()
        pid_filter_entry = ttk.Entry(filter_frame, textvariable=self.pid_filter_var, width=6)
        pid_filter_entry.pack(side=tk.LEFT, padx=(0,3))
        pid_filter_entry.bind("<Return>", lambda event: self.apply_filters())
        
        # Filtro por comando (volátil)
        ttk.Label(filter_frame, text="Command:").pack(side=tk.LEFT, padx=(5,2))
        self.cmd_filter_var = tk.StringVar()
        cmd_filter_entry = ttk.Entry(filter_frame, textvariable=self.cmd_filter_var, width=15)
        cmd_filter_entry.pack(side=tk.LEFT, padx=(0,3))
        cmd_filter_entry.bind("<Return>", lambda event: self.apply_filters())
        
        # Botão para aplicar filtros voláteis
        apply_btn = ttk.Button(filter_frame, text="Aplicar Filtros", 
                  command=self.apply_filters, width=12)
        apply_btn.pack(side=tk.LEFT, padx=2)
        
        # Botão para limpar filtros voláteis
        clear_btn = ttk.Button(filter_frame, text="Limpar Filtros", 
                  command=self.clear_filters, width=12)
        clear_btn.pack(side=tk.LEFT)
        
        # Frame para entrada de PIDs com instruções
        input_frame = ttk.LabelFrame(pid_frame, text="Seleção de PIDs")
        input_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(input_frame, 
                 text="Selecione PIDs na tabela ou digite manualmente (separados por espaço):").pack(anchor=tk.W, padx=5, pady=(2,0))
        
        self.pids_var = tk.StringVar()
        self.pids_entry = ttk.Entry(input_frame, textvariable=self.pids_var)
        self.pids_entry.pack(fill=tk.X, padx=5, pady=2)
        self.pids_entry.bind("<Return>", lambda event: self.kill_pids())
        
        # Frame para botões de ação
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
        
        # Treeview para mostrar processos com scrollbar
        tree_frame = ttk.Frame(pid_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0,2))
        
        columns = ('user', 'pid', 'idle', 'command')
        self.process_tree = ttk.Treeview(
            tree_frame, columns=columns, show='headings', selectmode='extended'
        )
        
        # Configurar cabeçalhos
        col_widths = [100, 70, 70, 380]
        for idx, col in enumerate(columns):
            self.process_tree.heading(
                col, 
                text=col.upper(), 
                anchor=tk.W,
                command=lambda c=col: self.treeview_sort_column(self.process_tree, c, False)
            )
            self.process_tree.column(col, width=col_widths[idx], anchor=tk.W)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Evento de seleção para adicionar PIDs
        self.process_tree.bind('<<TreeviewSelect>>', self.on_pid_select)
        
        # ===== ABA DERRUBAR MATRÍCULA E ROMANEIO (SEGUNDA ABA) =====
        matricula_frame = ttk.Frame(self.notebook)
        self.notebook.add(matricula_frame, text=" Derrubar Matrícula e Romaneio ")
        
        # Frame para entrada da matrícula
        input_frame = ttk.LabelFrame(matricula_frame, text="Consulta de PID")
        input_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(input_frame, text="Matrícula ou Romaneio:").pack(side=tk.LEFT, padx=(5,2))
        self.matricula_var = tk.StringVar()
        matricula_entry = ttk.Entry(input_frame, textvariable=self.matricula_var, width=15)
        matricula_entry.pack(side=tk.LEFT, padx=(0,5))
        matricula_entry.bind("<Return>", lambda event: self.consultar_matricula())
        
        # Botão alterado para "Consultar"
        self.consultar_matricula_btn = ttk.Button(
            input_frame, 
            text="Consultar", 
            command=self.consultar_matricula,
            width=10
        )
        self.consultar_matricula_btn.pack(side=tk.LEFT)
        
        # Frame de status da operação
        status_frame = ttk.LabelFrame(matricula_frame, text="Status da Operação")
        status_frame.pack(fill=tk.X, padx=5, pady=2)
        
        self.matricula_status_var = tk.StringVar(value="Aguardando operação...")
        ttk.Label(
            status_frame, 
            textvariable=self.matricula_status_var,
            font=('Segoe UI', 9, 'italic'),
            wraplength=900
        ).pack(fill=tk.X, padx=5, pady=2)
        
        # Frame para seleção de PIDs
        pid_select_frame = ttk.LabelFrame(matricula_frame, text="Seleção de PIDs")
        pid_select_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(pid_select_frame, 
                 text="Selecione PIDs na tabela ou digite manualmente (separados por espaço):").pack(anchor=tk.W, padx=5, pady=(2,0))
        
        self.matricula_pids_var = tk.StringVar()
        self.matricula_pids_entry = ttk.Entry(pid_select_frame, textvariable=self.matricula_pids_var)
        self.matricula_pids_entry.pack(fill=tk.X, padx=5, pady=2)
        self.matricula_pids_entry.bind("<Return>", lambda event: self.derrubar_pid_selecionado())
        
        # Frame para botões de ação
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
        
        # Tabela para resultados
        result_frame = ttk.LabelFrame(matricula_frame, text="Resultados da Consulta")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        # Treeview para mostrar resultados
        columns = ('user', 'pid', 'name')
        self.result_tree = ttk.Treeview(
            result_frame, 
            columns=columns, 
            show='headings',
            selectmode='extended'
        )
        
        # Configurar cabeçalhos com ordenação
        col_widths = [80, 60, 400]
        for idx, col in enumerate(columns):
            self.result_tree.heading(
                col, 
                text=col.upper(), 
                anchor=tk.W,
                command=lambda c=col: self.treeview_sort_column(self.result_tree, c, False)
            )
            self.result_tree.column(col, width=col_widths[idx], anchor=tk.W)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Vincular seleção na tabela ao campo de PIDs
        self.result_tree.bind('<<TreeviewSelect>>', self.on_matricula_pid_select)
        
        # ===== ABA CONSULTAR TELA (TERCEIRA ABA) =====
        tela_frame = ttk.Frame(self.notebook)
        self.notebook.add(tela_frame, text=" Consultar Tela ")
        
        # Frame para entrada da tela
        input_frame_tela = ttk.LabelFrame(tela_frame, text="Consulta de PID")
        input_frame_tela.pack(fill=tk.X, padx=5, pady=2)
        
        # ALTERAÇÃO SOLICITADA: TROCA DO RÓTULO PARA "Tela:"
        ttk.Label(input_frame_tela, text="Tela:").pack(side=tk.LEFT, padx=(5,2))
        
        # Campo pré-preenchido com asterisco
        self.tela_var = tk.StringVar(value="*")
        tela_entry = ttk.Entry(input_frame_tela, textvariable=self.tela_var, width=15)
        tela_entry.pack(side=tk.LEFT, padx=(0,5))
        tela_entry.bind("<Return>", lambda event: self.consultar_tela())
        
        # Botão para consultar tela
        self.consultar_tela_btn = ttk.Button(
            input_frame_tela, 
            text="Consultar Tela", 
            command=self.consultar_tela,
            width=13
        )
        self.consultar_tela_btn.pack(side=tk.LEFT)
        
        # Frame de status da operação
        status_frame_tela = ttk.LabelFrame(tela_frame, text="Status da Operação")
        status_frame_tela.pack(fill=tk.X, padx=5, pady=2)
        
        self.tela_status_var = tk.StringVar(value="Aguardando operação...")
        ttk.Label(
            status_frame_tela, 
            textvariable=self.tela_status_var,
            font=('Segoe UI', 9, 'italic'),
            wraplength=900
        ).pack(fill=tk.X, padx=5, pady=2)
        
        # Frame para seleção de PIDs
        pid_select_frame_tela = ttk.LabelFrame(tela_frame, text="Seleção de PIDs")
        pid_select_frame_tela.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(pid_select_frame_tela, 
                 text="Selecione PIDs na tabela ou digite manualmente (separados por espaço):").pack(anchor=tk.W, padx=5, pady=(2,0))
        
        self.tela_pids_var = tk.StringVar()
        self.tela_pids_entry = ttk.Entry(pid_select_frame_tela, textvariable=self.tela_pids_var)
        self.tela_pids_entry.pack(fill=tk.X, padx=5, pady=2)
        self.tela_pids_entry.bind("<Return>", lambda event: self.derrubar_pid_tela())
        
        # Frame para botões de ação
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
        
        # Tabela para resultados
        result_frame_tela = ttk.LabelFrame(tela_frame, text="Resultados da Consulta")
        result_frame_tela.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        # Treeview para mostrar resultados
        columns = ('user', 'pid', 'name')
        self.tela_tree = ttk.Treeview(
            result_frame_tela, 
            columns=columns, 
            show='headings',
            selectmode='extended'
        )
        
        # Configurar cabeçalhos com ordenação
        col_widths = [80, 60, 400]
        for idx, col in enumerate(columns):
            self.tela_tree.heading(
                col, 
                text=col.upper(), 
                anchor=tk.W,
                command=lambda c=col: self.treeview_sort_column(self.tela_tree, c, False)
            )
            self.tela_tree.column(col, width=col_widths[idx], anchor=tk.W)
        
        # Scrollbar
        scrollbar_tela = ttk.Scrollbar(result_frame_tela, orient=tk.VERTICAL, command=self.tela_tree.yview)
        self.tela_tree.configure(yscroll=scrollbar_tela.set)
        scrollbar_tela.pack(side=tk.RIGHT, fill=tk.Y)
        self.tela_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Vincular seleção na tabela ao campo de PIDs
        self.tela_tree.bind('<<TreeviewSelect>>', self.on_tela_pid_select)
        
        # ===== ABA TERMINAL INTERATIVO (QUARTA ABA) =====
        terminal_frame = ttk.Frame(self.notebook)
        self.notebook.add(terminal_frame, text=" Terminal Interativo ")
        
        # Terminal com fonte monoespaçada
        self.output_text = scrolledtext.ScrolledText(
            terminal_frame, wrap=tk.WORD, bg='#1e1e1e', fg='#d4d4d4', 
            insertbackground='white', font=('Consolas', 10)
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        self.output_text.config(state=tk.DISABLED)
        
        # Frame de comando com organização melhorada
        cmd_frame = ttk.Frame(terminal_frame)
        cmd_frame.pack(fill=tk.X, padx=5, pady=(0,2))
        
        ttk.Label(cmd_frame, text="Comando:").pack(side=tk.LEFT, padx=(0,5))
        
        self.cmd_var = tk.StringVar()
        self.cmd_entry = ttk.Entry(cmd_frame, textvariable=self.cmd_var, width=40)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        self.cmd_entry.bind("<Return>", self.send_command)
        
        send_btn = ttk.Button(cmd_frame, text="Enviar", command=self.send_command)
        send_btn.pack(side=tk.LEFT)
        
        # ===== ABA EXECUTAR COMANDOS (QUINTA ABA) =====
        commands_frame = ttk.Frame(self.notebook)
        self.notebook.add(commands_frame, text=" Executar Comandos ")
        
        # Frame de comandos com exemplo
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
        
        # Frame de resultados
        result_frame = ttk.Frame(commands_frame)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0,2))
        
        ttk.Label(result_frame, text="Resultados:", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)
        
        self.result_text = scrolledtext.ScrolledText(
            result_frame, wrap=tk.WORD, bg='#1e1e1e', fg='#d4d4d4', 
            font=('Consolas', 10), state=tk.DISABLED
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Configurar foco
        self.password_entry.focus_set()
        
        # ===== RODAPÉ FIXO =====
        footer_frame = ttk.Frame(root, relief=tk.SUNKEN, padding=(5, 3))
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status da conexão (esquerda)
        self.connection_status = tk.StringVar(value="Status: Desconectado")
        status_label = ttk.Label(footer_frame, textvariable=self.connection_status)
        status_label.pack(side=tk.LEFT, padx=5)
        
        # Direitos autorais e hiperlink (direita)
        copyright_frame = ttk.Frame(footer_frame)
        copyright_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(copyright_frame, text=f"© 2024 Franklin Tadeu v{SOFTWARE_VERSION}").pack(side=tk.LEFT)
        
        # Hiperlink para LinkedIn
        link_label = ttk.Label(
            copyright_frame, 
            text="LinkedIn", 
            foreground="blue", 
            cursor="hand2"
        )
        link_label.pack(side=tk.LEFT, padx=(5, 0))
        link_label.bind("<Button-1>", lambda e: webbrowser.open("https://www.linkedin.com/in/franklintadeu/"))
        
        # Contato WhatsApp
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
        
        # Botão para verificar atualizações
        update_btn = ttk.Button(
            footer_frame, 
            text="Verificar Atualizações",
            command=self.check_for_updates
        )
        update_btn.pack(side=tk.RIGHT, padx=5)
        
        # Configurar fechamento seguro
        root.protocol("WM_DELETE_WINDOW", self.safe_close)

        # Variáveis para captura de saída
        self.capturing_matricula = False
        self.matricula_output = ""
        self.capturing_tela = False
        self.tela_output = ""
        
        # Configurar atalhos de teclado
        self.setup_treeview_bindings()

    # Geração de salt único baseado no host
    @classmethod
    def generate_salt(cls):
        """Gera salt único baseado no nome do host"""
        hostname = socket.gethostname().encode()
        return hashlib.sha256(hostname).digest()[:16]

    @staticmethod
    def get_master_key():
        """Retorna chave mestra ofuscada"""
        parts = [
            "c0mpl3xP@ss_",
            "w1thS0m3R@nd0m",
            "5tringAndNumb3rs",
            "!@#$%^&*()"
        ]
        return "".join(parts)

    @classmethod
    def derive_key(cls, salt=None):
        """Deriva chave criptográfica a partir da chave mestra"""
        if salt is None:
            salt = cls.generate_salt()
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 32 para AES + 32 para HMAC
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(cls.get_master_key().encode())

    @classmethod
    def encrypt_data(cls, plaintext):
        """Criptografa dados sensíveis com verificação de integridade"""
        try:
            salt = cls.generate_salt()
            key = cls.derive_key(salt)
            aes_key = key[:32]
            hmac_key = key[32:]
            iv = os.urandom(16)
            
            # Criptografia
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # HMAC para verificação de integridade
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext)
            tag = h.finalize()
            
            return base64.b64encode(salt + iv + ciphertext + tag).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return plaintext  # Fallback para texto claro

    @classmethod
    def decrypt_data(cls, ciphertext_b64):
        """Descriptografa dados sensíveis com verificação de integridade"""
        try:
            data = base64.b64decode(ciphertext_b64)
            
            # Verificar tamanho mínimo
            if len(data) < (16 + 16 + 32):  # Salt(16) + IV(16) + HMAC(32)
                logger.error("Decryption error: Data too short")
                return ciphertext_b64
                
            salt = data[:16]
            iv = data[16:32]
            ciphertext = data[32:-32]
            tag = data[-32:]
            
            key = cls.derive_key(salt)
            aes_key = key[:32]
            hmac_key = key[32:]
            
            # Verificar integridade com HMAC
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext)
            try:
                h.verify(tag)
            except (InvalidTag, InvalidSignature) as e:
                logger.error(f"HMAC verification failed: {e}")
                return ciphertext_b64
                
            # Descriptografia
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remover padding com tratamento de erros
            unpadder = padding.PKCS7(128).unpadder()
            try:
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                return plaintext.decode()
            except ValueError as e:
                logger.error(f"Padding error: {e}")
                # Tentar retornar sem remover padding (pode ser dado sem padding)
                return padded_plaintext.decode(errors='ignore')
                
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return ciphertext_b64

    def load_admin_config(self):
        """Carrega a configuração do administrador do arquivo"""
        # Hash da senha master fixa
        MASTER_PASSWORD = "Carro@#356074"  # Isso será usado apenas para gerar o hash
        master_password_hash = hashlib.sha256(MASTER_PASSWORD.encode()).hexdigest()
        
        default_config = {
            'admin_password': self.encrypt_data('admin'),
            'master_password_hash': master_password_hash,
            'update_url': self.DEFAULT_UPDATE_URL
        }
        
        config_path = self.admin_config_file
        
        # Se o arquivo não existe, retornar os valores padrão
        if not os.path.exists(config_path):
            return default_config
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Preencher com valores padrão se alguma chave estiver faltando
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
            
            return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return default_config

    def save_admin_config(self, config):
        """Salva a configuração do administrador"""
        config_to_save = config.copy()
        
        # Criptografar senha admin se necessário
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
        """Tenta carregar o ícone da aplicação com fallbacks silenciosos"""
        icon_found = False
        base_paths = []
        
        # Verificar caminhos possíveis
        if getattr(sys, 'frozen', False):
            base_paths.append(sys._MEIPASS)  # Diretório do executável empacotado
        base_paths.append(os.path.dirname(os.path.abspath(__file__)))  # Diretório do script
        base_paths.append(os.getcwd())  # Diretório de trabalho atual
        
        # Tentar múltiplos nomes de arquivo possíveis
        icon_filenames = [
            "logoicogrupoprofarma.ico",  # Prioridade para o formato .ico
            "logoicogrupoprofarma.png",  # Nome original
            "logo.ico",                  # Nomes alternativos
            "icon.ico",
            "app_icon.ico",
            "logo.png",
            "icon.png"
        ]
        
        for base_path in base_paths:
            for icon_name in icon_filenames:
                try:
                    image_path = os.path.join(base_path, icon_name)
                    if os.path.exists(image_path):
                        # Tentar carregar diretamente como ícone
                        if icon_name.endswith('.ico'):
                            self.root.iconbitmap(image_path)
                            icon_found = True
                            logger.info(f"Ícone carregado: {image_path}")
                            break
                        else:
                            # Converter imagem para ícone
                            img_icon = Image.open(image_path)
                            img_icon = img_icon.resize((32, 32), Image.LANCZOS)
                            
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.ico') as temp_ico:
                                img_icon.save(temp_ico.name, format='ICO')
                                self.temp_ico_file = temp_ico.name
                            
                            self.root.iconbitmap(self.temp_ico_file)
                            icon_found = True
                            logger.info(f"Ícone convertido e carregado: {image_path}")
                            break
                except Exception as e:
                    logger.error(f"Erro ao carregar ícone: {str(e)}")
                    continue
            if icon_found:
                break
        
        # Fallback para ícone padrão se nenhum for encontrado
        if not icon_found:
            try:
                self.root.iconbitmap(default='')
                logger.warning("Usando ícone padrão do sistema")
            except Exception:
                logger.error("Falha ao carregar qualquer ícone")

    def setup_treeview_bindings(self):
        """Configura atalhos de teclado para as treeviews"""
        for tree in [self.process_tree, self.result_tree, self.tela_tree]:
            tree.bind("<Control-a>", self.select_all_treeview)
            tree.bind("<Control-A>", self.select_all_treeview)  # Caps Lock

    def select_all_treeview(self, event):
        """Seleciona todos os itens na treeview"""
        tree = event.widget
        tree.selection_set(tree.get_children())
        return "break"  # Prevenir comportamento padrão

    def show_admin_dialog(self):
        """Mostra a janela de diálogo para autenticação de administração"""
        # Janela de diálogo para senha de administração
        top = tk.Toplevel(self.root)
        self.admin_dialog = top  # Armazenar referência para a janela de admin
        top.title("Configuração de Filtro Permanente")
        top.geometry("500x400")
        top.resizable(False, False)
        top.transient(self.root)
        top.grab_set()
        
        # Tenta carregar o ícone na janela de admin
        try:
            if self.temp_ico_file:
                top.iconbitmap(self.temp_ico_file)
            else:
                # Tentar carregar o ícone novamente
                self.load_application_icon()
                if self.temp_ico_file:
                    top.iconbitmap(self.temp_ico_file)
        except Exception:
            pass
        
        # Frame principal
        main_frame = ttk.Frame(top, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Frame de seleção de tipo de administrador
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
        
        # Autenticação
        auth_frame = ttk.LabelFrame(main_frame, text="Autenticação")
        auth_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Frame para senha de administrador normal
        admin_pass_frame = ttk.Frame(auth_frame)
        admin_pass_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(admin_pass_frame, text="Senha:").pack(side=tk.LEFT, padx=(5,2))
        
        senha_var = tk.StringVar()
        senha_entry = ttk.Entry(admin_pass_frame, textvariable=senha_var, show="*", width=15)
        senha_entry.pack(side=tk.LEFT, padx=(0,5))
        senha_entry.focus_set()
        # CORREÇÃO: Adicionar bind de Enter
        senha_entry.bind("<Return>", lambda event: check_password())
        
        # Função local para verificar senha
        def check_password():
            admin_type = admin_type_var.get()
            password = senha_var.get()
            
            if admin_type == "admin":
                stored_pass = self.admin_config.get('admin_password', 'admin')
                # Descriptografar se necessário
                if stored_pass != 'admin' and re.match(r'^[A-Za-z0-9+/]+={0,2}$', stored_pass):
                    stored_pass = self.decrypt_data(stored_pass) or 'admin'
                    
                if password == stored_pass:
                    # Esconder elementos de autenticação
                    auth_frame.pack_forget()
                    type_frame.pack_forget()
                    
                    # Mostrar configurações de administrador normal
                    config_frame.pack(fill=tk.BOTH, expand=True)
                    top.geometry("500x400")
                else:
                    messagebox.showerror("Erro", 
                        "Senha incorreta! A senha padrão é 'admin'. "
                        "Se você a alterou e esqueceu, clique em 'Esqueci a senha'.",
                        parent=top)
                    senha_entry.focus_set()
            
            elif admin_type == "master":
                # Verificar usando o hash armazenado
                stored_hash = self.admin_config.get('master_password_hash')
                input_hash = hashlib.sha256(password.encode()).hexdigest()
                
                if stored_hash and input_hash == stored_hash:
                    # Esconder elementos de autenticação
                    auth_frame.pack_forget()
                    type_frame.pack_forget()
                    
                    # Mostrar configurações de administrador master
                    master_config_frame.pack(fill=tk.BOTH, expand=True)
                    top.geometry("500x400")
                else:
                    messagebox.showerror("Erro", 
                        "Senha master incorreta!",
                        parent=top)
                    senha_entry.focus_set()
        
        # Função local para senha esquecida
        def forgot_password():
            config_path = os.path.abspath(self.admin_config_file)
            messagebox.showinfo(
                "Esqueci a senha",
                f"Para redefinir as senhas, exclua ou edite o arquivo de configuração:\n\n{config_path}\n\n"
                "Após excluir, as senhas voltarão aos valores padrão (admin para administrador normal).",
                parent=self.root
            )
        
        # Botão para validar
        auth_btn = ttk.Button(admin_pass_frame, text="Validar", 
                             command=check_password, width=8)
        auth_btn.pack(side=tk.LEFT, padx=5)
        
        # Botão "Esqueci a senha" ao lado do Validar
        ttk.Button(
            admin_pass_frame, 
            text="Esqueci a senha", 
            command=forgot_password,
            width=15
        ).pack(side=tk.LEFT, padx=5)
        
        # Frame de configuração para administrador normal (inicialmente oculto)
        config_frame = ttk.Frame(main_frame)
        
        # Frame para usuários
        users_frame = ttk.LabelFrame(config_frame, text="Usuários Bloqueados (um por linha)")
        users_frame.pack(fill=tk.X, pady=5)
        
        self.users_text = scrolledtext.ScrolledText(users_frame, height=5, font=('Consolas', 9))
        self.users_text.pack(fill=tk.X, padx=5, pady=5)
        self.users_text.insert(tk.END, "\n".join(self.permanent_filter['users']))
        
        # Frame para comandos
        commands_frame = ttk.LabelFrame(config_frame, text="Comandos Bloqueados (um por linha)")
        commands_frame.pack(fill=tk.X, pady=5)
        
        self.commands_text = scrolledtext.ScrolledText(commands_frame, height=5, font=('Consolas', 9))
        self.commands_text.pack(fill=tk.X, padx=5, pady=5)
        self.commands_text.insert(tk.END, "\n".join(self.permanent_filter['commands']))
        
        # Botões de ação
        btn_frame = ttk.Frame(config_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        def save_admin_config():
            users = self.users_text.get("1.0", tk.END).splitlines()
            commands = self.commands_text.get("1.0", tk.END).splitlines()
            
            # Filtrar linhas vazias
            self.permanent_filter['users'] = [u.strip() for u in users if u.strip()]
            self.permanent_filter['commands'] = [c.strip() for c in commands if c.strip()]
            
            # Atualizar lista global de filtros permanentes
            global PERMANENT_FILTER_USERS, PERMANENT_FILTER_COMMANDS
            PERMANENT_FILTER_USERS = self.permanent_filter['users']
            PERMANENT_FILTER_COMMANDS = self.permanent_filter['commands']
            
            # Atualizar configuração para salvar
            self.admin_config['permanent_filter_users'] = self.permanent_filter['users']
            self.admin_config['permanent_filter_commands'] = self.permanent_filter['commands']
            self.save_admin_config(self.admin_config)
            
            messagebox.showinfo("Sucesso", "Configuração salva com sucesso!", parent=top)
            top.destroy()
            
            # Atualizar lista de processos se estiver conectado
            if self.client:
                self.list_processes()
        
        save_btn = ttk.Button(btn_frame, text="Salvar Configuração", command=save_admin_config, style='Green.TButton')
        save_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = ttk.Button(btn_frame, text="Cancelar", command=top.destroy)
        cancel_btn.pack(side=tk.LEFT)
        
        # Frame de configuração para administrador master (inicialmente oculto)
        master_config_frame = ttk.Frame(main_frame)
        
        # Frame para URL de atualização
        url_frame = ttk.LabelFrame(master_config_frame, text="URL de Atualização")
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="Endpoint para verificar atualizações:").pack(anchor=tk.W, padx=5, pady=(2,0))
        
        update_url_var = tk.StringVar(value=self.admin_config.get('update_url', self.DEFAULT_UPDATE_URL))
        update_url_entry = ttk.Entry(url_frame, textvariable=update_url_var, width=50)
        update_url_entry.pack(fill=tk.X, padx=5, pady=2)
        
        # Frame para senha de administrador
        admin_pass_frame = ttk.LabelFrame(master_config_frame, text="Senha do Administrador")
        admin_pass_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(admin_pass_frame, text="Nova senha:").pack(side=tk.LEFT, padx=(5,2))
        new_admin_pass_var = tk.StringVar()
        new_admin_pass_entry = ttk.Entry(admin_pass_frame, textvariable=new_admin_pass_var, show="*", width=15)
        new_admin_pass_entry.pack(side=tk.LEFT, padx=(0,5))
        
        # Frame para senha master
        master_pass_frame = ttk.LabelFrame(master_config_frame, text="Senha Master")
        master_pass_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(master_pass_frame, text="Nova senha master:").pack(side=tk.LEFT, padx=(5,2))
        new_master_pass_var = tk.StringVar()
        new_master_pass_entry = ttk.Entry(master_pass_frame, textvariable=new_master_pass_var, show="*", width=15)
        new_master_pass_entry.pack(side=tk.LEFT, padx=(0,5))
        
        # Botões de ação para master
        master_btn_frame = ttk.Frame(master_config_frame)
        master_btn_frame.pack(fill=tk.X, pady=10)
        
        def save_master_config():
            # Atualizar senhas se fornecidas
            new_admin_pass = new_admin_pass_var.get().strip()
            new_master_pass = new_master_pass_var.get().strip()
            
            if new_admin_pass:
                self.admin_config['admin_password'] = new_admin_pass
            if new_master_pass:
                # Atualizar o hash da senha master
                self.admin_config['master_password_hash'] = hashlib.sha256(new_master_pass.encode()).hexdigest()
            
            # Atualizar URL de atualização
            self.admin_config['update_url'] = update_url_var.get().strip()
            
            # Salvar configuração
            if self.save_admin_config(self.admin_config):
                messagebox.showinfo("Sucesso", "Configuração master salva com sucesso!", parent=top)
                top.destroy()
            else:
                messagebox.showerror("Erro", "Falha ao salvar configuração!", parent=top)
        
        save_btn = ttk.Button(master_btn_frame, text="Salvar Configuração", command=save_master_config, style='Green.TButton')
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # NOVO BOTÃO: Gerar Executável
        generate_exe_btn = ttk.Button(
            master_btn_frame, 
            text="Gerar Executável",
            command=self.generate_executable,
            style='Green.TButton'
        )
        generate_exe_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = ttk.Button(master_btn_frame, text="Cancelar", command=top.destroy)
        cancel_btn.pack(side=tk.LEFT)
        
        # ===== NOVO: FRAME PARA PROGRESSO DA GERAÇÃO DE EXECUTÁVEL =====
        self.progress_frame = ttk.Frame(master_config_frame)
        self.progress_frame.pack(fill=tk.X, pady=5, padx=5)
        
        self.progress_label = ttk.Label(self.progress_frame, text="", anchor=tk.W)
        self.progress_label.pack(fill=tk.X, pady=(0,2))
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='determinate', length=380)
        self.progress_bar.pack(fill=tk.X, pady=(0,5))
        
        # Inicialmente oculto
        self.progress_frame.pack_forget()
        
        # Centralizar a janela
        top.update_idletasks()
        width = top.winfo_width()
        height = top.winfo_height()
        x = (top.winfo_screenwidth() // 2) - (width // 2)
        y = (top.winfo_screenheight() // 2) - (height // 2)
        top.geometry(f"{width}x{height}+{x}+{y}")

        # Função para atualizar a interface de autenticação conforme o tipo
        def update_auth_ui(*args):
            if admin_type_var.get() == "admin":
                admin_pass_frame.pack(fill=tk.X, pady=5)
            else:  # Master
                admin_pass_frame.pack(fill=tk.X, pady=5)
        
        # Chamar a função para configurar a interface inicialmente
        update_auth_ui()
        
        # Rastrear mudanças na variável
        admin_type_var.trace_add("write", lambda *args: update_auth_ui())

    def update_progress(self, value, message):
        """Atualiza a barra de progresso e mensagem na janela de admin"""
        if self.admin_dialog and self.admin_dialog.winfo_exists():
            self.progress_bar['value'] = value
            self.progress_label.config(text=message)
            self.admin_dialog.update()

    def generate_executable(self):
        """Gera um executável do aplicativo usando PyInstaller com barra de progresso"""
        # Mostrar o frame de progresso
        self.progress_frame.pack(fill=tk.X, pady=5, padx=5)
        self.update_progress(0, "Preparando para gerar executável...")
        
        # Iniciar a thread de geração
        threading.Thread(target=self._generate_executable_thread, daemon=True).start()

    def _generate_executable_thread(self):
        """Executa a geração do executável em segundo plano com progresso real"""
        try:
            # Passo 1: Criar script temporário (10%)
            self.update_progress(10, "Criando script temporário...")
            temp_script_path = self.create_temp_script_with_filters()
            
            # Passo 2: Verificar PyInstaller (20%)
            self.update_progress(20, "Verificando dependências...")
            try:
                import PyInstaller
            except ImportError:
                # Instalar PyInstaller se necessário
                self.update_progress(30, "Instalando PyInstaller...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            
            # Localizar o arquivo de ícone
            icon_path = None
            base_paths = [os.path.dirname(os.path.abspath(__file__)), os.getcwd()]
            if getattr(sys, 'frozen', False):
                base_paths.insert(0, sys._MEIPASS)
            
            # Priorizar ícones .ico
            icon_names = [
                "logoicogrupoprofarma.ico", 
                "logo.ico", 
                "icon.ico",
                "logoicogrupoprofarma.png",
                "logo.png"
            ]
            
            for base_path in base_paths:
                for icon_name in icon_names:
                    candidate = os.path.join(base_path, icon_name)
                    if os.path.exists(candidate):
                        icon_path = candidate
                        break
                if icon_path:
                    break
            
            # Passo 3: Configurar comando PyInstaller (30%)
            self.update_progress(40, "Configurando processo de compilação...")
            cmd = [
                sys.executable,
                "-m",
                "PyInstaller",
                "--onefile",
                "--windowed",
                "--name=GerenciadorSSH",
            ]
            
            # Adicionar ícone se encontrado
            if icon_path:
                cmd.append(f"--icon={icon_path}")
                self.update_progress(45, f"Usando ícone: {os.path.basename(icon_path)}")
            
            # Adicionar dados adicionais (se houver)
            if os.path.exists("logoicogrupoprofarma.png"):
                cmd.append("--add-data=logoicogrupoprofarma.png;.")
            
            cmd.append(temp_script_path)
            
            # Filtrar argumentos vazios (não deve ser necessário, mas por segurança)
            cmd = [arg for arg in cmd if arg]
            
            # Passo 4: Executar PyInstaller (40%-90%)
            self.update_progress(50, "Compilando aplicativo (pode demorar alguns minutos)...")
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW  # Evita janelas pop-up
            )
            
            # Simular progresso durante a compilação
            progress = 50
            while process.poll() is None:
                time.sleep(0.5)
                progress = min(progress + 1, 90)
                self.update_progress(progress, f"Compilando... {progress}%")
            
            # Processar resultado (90%-100%)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                self.update_progress(100, "Executável gerado com sucesso na pasta 'dist'!")
            else:
                error_msg = f"Erro ao gerar executável:\n\n{stderr.decode(errors='ignore')}"
                self.update_progress(100, error_msg)
            
            # Excluir o script temporário
            try:
                os.unlink(temp_script_path)
            except Exception:
                pass
            
        except Exception as e:
            self.update_progress(100, f"Falha ao gerar executável: {str(e)}")
        finally:
            # Manter a barra de progresso visível com o resultado final
            pass

    def create_temp_script_with_filters(self):
        """Cria um script temporário com os filtros permanentes atualizados"""
        # Ler o conteúdo do script atual
        current_script = os.path.abspath(__file__)
        with open(current_script, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Encontrar as linhas que definem as listas de filtros e a versão
        new_lines = []
        for line in lines:
            stripped_line = line.strip()
            if stripped_line.startswith('PERMANENT_FILTER_USERS ='):
                # Substituir pela lista atual da configuração
                users = self.admin_config.get('permanent_filter_users', PERMANENT_FILTER_USERS)
                new_line = f"PERMANENT_FILTER_USERS = {users}\n"
                new_lines.append(new_line)
            elif stripped_line.startswith('PERMANENT_FILTER_COMMANDS ='):
                commands = self.admin_config.get('permanent_filter_commands', PERMANENT_FILTER_COMMANDS)
                new_line = f"PERMANENT_FILTER_COMMANDS = {commands}\n"
                new_lines.append(new_line)
            elif stripped_line.startswith('SOFTWARE_VERSION ='):
                # Atualizar a versão para a atual
                new_line = f'SOFTWARE_VERSION = "{SOFTWARE_VERSION}"\n'
                new_lines.append(new_line)
            else:
                new_lines.append(line)
    
        # Escrever o script temporário
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.py', delete=False) as temp_script:
            temp_script.writelines(new_lines)
            return temp_script.name

    def check_for_updates(self):
        """Verifica se há atualizações disponíveis para o software"""
        try:
            # Obter URL de atualização da configuração
            update_url = self.admin_config.get('update_url', self.DEFAULT_UPDATE_URL)
            
            # Adicionar headers para evitar erro 403
            headers = {"User-Agent": "SSHManager/1.0"}
            req = urllib.request.Request(update_url, headers=headers)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                latest_version = data.get('version')
                
                # Selecionar URL de download apropriada
                if IS_EXE:
                    download_url = data.get('exe_url')
                else:
                    download_url = data.get('py_url')
                
                if latest_version and download_url:
                    # Comparar versões
                    if self.compare_versions(SOFTWARE_VERSION, latest_version) < 0:
                        # Nova versão disponível
                        response = messagebox.askyesno(
                            "Atualização Disponível",
                            f"Uma nova versão ({latest_version}) está disponível!\n\n"
                            f"Deseja atualizar agora?",
                            parent=self.root
                        )
                        
                        if response:
                            self.download_and_update(download_url)
                    else:
                        messagebox.showinfo(
                            "Sem Atualizações",
                            "Você já está usando a versão mais recente do software.",
                            parent=self.root
                        )
                else:
                    messagebox.showerror(
                        "Erro",
                        "Não foi possível verificar atualizações. Formato inválido.",
                        parent=self.root
                    )
        except Exception as e:
            messagebox.showerror(
                "Erro",
                f"Falha ao verificar atualizações: {str(e)}",
                parent=self.root
            )

    def compare_versions(self, current, latest):
        """Compara duas versões no formato 'X.Y.Z'"""
        current_parts = list(map(int, current.split('.')))
        latest_parts = list(map(int, latest.split('.')))
        
        # Preencher com zeros se necessário
        while len(current_parts) < 3:
            current_parts.append(0)
        while len(latest_parts) < 3:
            latest_parts.append(0)
            
        # Comparar cada parte
        for c, l in zip(current_parts, latest_parts):
            if c < l:
                return -1
            elif c > l:
                return 1
        return 0

    def download_and_update(self, download_url):
        """Baixa e instala a atualização"""
        try:
            # Criar diretório temporário
            temp_dir = tempfile.mkdtemp()
            
            # Nome do arquivo temporário
            if IS_EXE:
                temp_file = os.path.join(temp_dir, "update.exe")
            else:
                temp_file = os.path.join(temp_dir, "update.py")
            
            # Baixar a nova versão
            with urllib.request.urlopen(download_url, timeout=30) as response:
                with open(temp_file, 'wb') as out_file:
                    shutil.copyfileobj(response, out_file)
            
            # Se for Windows, criar um script .bat para atualizar
            if sys.platform.startswith('win'):
                # Determinar o caminho do executável/script atual
                current_path = os.path.abspath(sys.argv[0])
                
                # Criar script de atualização
                script = f"""@echo off
timeout /t 3 /nobreak >nul
"""
                # Se for um executável, podemos simplesmente substituir
                if IS_EXE:
                    script += f'taskkill /F /IM "{os.path.basename(current_path)}" >nul 2>&1\n'
                    script += f'move /Y "{temp_file}" "{current_path}"\n'
                    script += f'start "" "{current_path}"\n'
                else:
                    # Para script Python, precisamos matar o processo Python que está executando este script
                    script += f'taskkill /F /IM "python.exe" >nul 2>&1\n'
                    script += f'del /F /Q "{current_path}"\n'
                    script += f'move /Y "{temp_file}" "{current_path}"\n'
                    script += f'start "" "{current_path}"\n'
                
                script += f'rmdir /s /q "{temp_dir}"\n'
                script += 'del "%~f0"'
                
                script_file = os.path.join(temp_dir, "update.bat")
                with open(script_file, 'w') as f:
                    f.write(script)
                
                # Executar o script e fechar o aplicativo
                subprocess.Popen([script_file], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                self.safe_close()
            else:
                # Para outros sistemas, apenas informar o usuário
                messagebox.showinfo(
                    "Atualização Baixada",
                    f"A nova versão foi baixada em:\n{temp_file}\n"
                    "Por favor, instale manualmente.",
                    parent=self.root
                )
            
            return True
        except Exception as e:
            messagebox.showerror(
                "Erro na Atualização",
                f"Falha ao baixar/instalar atualização: {str(e)}",
                parent=self.root
            )
            return False

    def is_caps_lock_on(self):
        """Verifica se o Caps Lock está ativo (Windows)"""
        if sys.platform.startswith('win'):
            hll_dll = ctypes.WinDLL("User32.dll")
            return hll_dll.GetKeyState(0x14) & 0xffff != 0
        # Para outros sistemas, retorna False por padrão
        return False

    def toggle_password_visibility(self):
        """Alterna a visibilidade da senha"""
        self.show_password = not self.show_password
        if self.show_password:
            self.password_entry.config(show="")
            self.eye_button.config(text="🔒")
        else:
            self.password_entry.config(show="*")
            self.eye_button.config(text="👁")
        
        # Devolver o foco para o campo de senha para que o Enter funcione
        self.password_entry.focus_set()

    def on_password_focus_in(self, event):
        """Verifica Caps Lock quando o campo de senha ganha foco"""
        if self.is_caps_lock_on():
            messagebox.showwarning("Aviso", "CAPS LOCK está ativado!", parent=self.root)
            self.caps_lock_warning_shown = True
        else:
            self.caps_lock_warning_shown = False  # Resetar aviso

    def on_password_key_release(self, event):
        """Verifica Caps Lock quando uma tecla é liberada no campo de senha"""
        # Verificar apenas se o Caps Lock está ativado e ainda não foi mostrado o aviso
        if self.is_caps_lock_on() and not self.caps_lock_warning_shown:
            messagebox.showwarning("Aviso", "CAPS LOCK está ativado!", parent=self.root)
            self.caps_lock_warning_shown = True
        elif not self.is_caps_lock_on():
            self.caps_lock_warning_shown = False

    def safe_close(self):
        """Fecha a aplicação de forma segura"""
        self.running = False
        self.disconnect()
        
        # Remover arquivo temporário do ícone se existir
        if self.temp_ico_file and os.path.exists(self.temp_ico_file):
            try:
                os.unlink(self.temp_ico_file)
            except Exception:
                pass
                
        self.root.destroy()

    def show_help(self):
        """Mostra as instruções de uso em uma janela com scroll atualizadas"""
        # Criar uma nova janela
        help_window = tk.Toplevel(self.root)
        help_window.title("Ajuda - Instruções de Uso")
        help_window.geometry("900x650")
        help_window.resizable(True, True)
        help_window.transient(self.root)
        help_window.grab_set()
        
        # Frame principal
        main_frame = ttk.Frame(help_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Texto de ajuda expandido e atualizado
        instructions = (
            "MANUAL COMPLETO DO GERENCIADOR SSH AVANÇADO\n\n"
            
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
            
            "8. GERAÇÃO DE EXECUTÁVEL\n"
            "   - Disponível para administradores master\n"
            "   - Gera versão .exe do aplicativo\n"
            "   - Barra de progresso mostra andamento real\n"
            "   - Pode levar alguns minutos para completar\n\n"
            
            "9. ATUALIZAÇÕES\n"
            "   - Botão 'Verificar Atualizações' no rodapé\n"
            "   - O software busca automaticamente novas versões\n\n"
            
            "10. DICAS AVANÇADAS\n"
            "   - Pressione Enter em campos de texto para ativar ações\n"
            "   - Clique nos cabeçalhos das tabelas para ordenar\n"
            "   - Use o botão 👁 para mostrar/ocultar senha\n"
            "   - Para selecionar todos os PIDs em uma tabela: Ctrl+A\n"
            "   - Para limpar seleção: clique em área vazia da tabela\n\n"
            
            "11. SEGURANÇA\n"
            "   - Host keys são verificadas e armazenadas\n"
            "   - Senhas administrativas são criptografadas\n"
            "   - Conexões usam protocolo SSH seguro\n\n"
            
            "CONTATO E SUPORTE:\n"
            "   WhatsApp: 31 99363-9500\n"
            "   LinkedIn: https://www.linkedin.com/in/franklintadeu/\n\n"
            
            "VERSÃO ATUAL: " + SOFTWARE_VERSION
        )
        
        # Widget de texto com scroll
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
        
        # Botão de fechar
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10,0))
        
        close_btn = ttk.Button(
            btn_frame, 
            text="Fechar", 
            command=help_window.destroy,
            width=10
        )
        close_btn.pack()
        
        # Centralizar a janela
        self.center_window(help_window)

    def center_window(self, window):
        """Centraliza qualquer janela na tela"""
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        window.geometry(f"+{x}+{y}")

    def load_host_history(self):
        """Carrega o histórico de hosts do arquivo de configuração"""
        history = []
        config_path = os.path.expanduser("~/.ssh_tool_history")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    history = [line.strip() for line in f.readlines()]
            except Exception:
                pass
        return list(set(history))  # Remover duplicatas

    def save_host_history(self, host):
        """Salva o host no histórico"""
        if host not in self.host_history:
            self.host_history.append(host)
            
        config_path = os.path.expanduser("~/.ssh_tool_history")
        try:
            with open(config_path, 'w') as f:
                f.write("\n".join(self.host_history))
        except Exception:
            pass
            
        # Atualizar combobox
        self.host_combo['values'] = self.host_history

    def on_host_selected(self, event=None):
        """Chamado quando um novo host é selecionado no combobox"""
        new_host = self.host_var.get()
        
        # Se estiver conectado a um host diferente
        if self.client and self.current_host != new_host:
            self.disconnect()

    def treeview_sort_column(self, tv, col, reverse):
        """Ordena as colunas ao clicar no cabeçalho"""
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        
        try:
            # Ordenação numérica para PID e Idle
            if col in ('pid', 'idle'):
                # Converter para float, tratar valores vazias como 0
                l.sort(key=lambda t: float(t[0]) if t[0].strip() else 0.0, reverse=reverse)
            else:
                l.sort(key=lambda t: t[0].lower(), reverse=reverse)
        except ValueError:
            l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)
        
        tv.heading(col, command=lambda: self.treeview_sort_column(tv, col, not reverse))

    def on_pid_select(self, event):
        """Adiciona PIDs selecionados ao campo de entrada"""
        selected_pids = []
        for item in self.process_tree.selection():
            pid = self.process_tree.item(item, 'values')[1]
            selected_pids.append(pid)
        
        self.pids_var.set(" ".join(selected_pids))
    
    def on_matricula_pid_select(self, event):
        """Adiciona PIDs selecionados ao campo de entrada da matrícula"""
        selected_pids = []
        for item in self.result_tree.selection():
            values = self.result_tree.item(item, 'values')
            if len(values) >= 2:  # Garantir que temos pelo menos USER e PID
                pid = values[1]  # PID está na segunda coluna
                selected_pids.append(pid)
        
        self.matricula_pids_var.set(" ".join(selected_pids))
    
    def on_tela_pid_select(self, event):
        """Adiciona PIDs selecionados ao campo de entrada da tela"""
        selected_pids = []
        for item in self.tela_tree.selection():
            values = self.tela_tree.item(item, 'values')
            if len(values) >= 2:  # Garantir que temos pelo menos USER e PID
                pid = values[1]  # PID está na segunda coluna
                selected_pids.append(pid)
        
        self.tela_pids_var.set(" ".join(selected_pids))

    def apply_filters(self):
        """Aplica os filtros voláteis na lista de processos"""
        # Obter valores dos filtros voláteis
        user_filter = self.user_filter_var.get().lower().strip()
        pid_filter = self.pid_filter_var.get().strip()
        cmd_filter = self.cmd_filter_var.get().lower().strip()
        
        # Limpar a treeview
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Adicionar apenas processos que correspondem aos filtros voláteis
        for proc in self.all_processes:
            user_match = not user_filter or user_filter in proc['user'].lower()
            pid_match = not pid_filter or pid_filter in proc['pid']
            cmd_match = not cmd_filter or cmd_filter in proc['command'].lower()
            
            if user_match and pid_match and cmd_match:
                self.add_process_to_tree(proc)

    def clear_filters(self):
        """Limpa todos os filtros voláteis e mostra todos os processos"""
        self.user_filter_var.set("")
        self.pid_filter_var.set("")
        self.cmd_filter_var.set("")
        
        # Limpar e recarregar todos os processos
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        for proc in self.all_processes:
            self.add_process_to_tree(proc)

    def append_output(self, text):
        """Adiciona texto ao terminal interativo"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        
        # Se estivermos capturando a saída para matrícula, adicionar ao buffer
        if self.capturing_matricula:
            self.matricula_output += text
        
        # Se estivermos capturando a saída para tela, adicionar ao buffer
        if self.capturing_tela:
            self.tela_output += text

    def append_result(self, text):
        """Adiciona texto à área de resultados de comandos"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

    def connect(self):
        """Estabelece conexão SSH com o servidor"""
        # Se já estiver conectado a um host diferente, desconecta primeiro
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
            # Atualizar status da conexão
            self.connection_status.set(f"Status: Conectado a {host}")
            # Listar processos automaticamente após conectar
            self.list_processes()

    def disconnect(self):
        """Fecha a conexão SSH com o servidor"""
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
                # Atualizar status da conexão
                self.connection_status.set("Status: Desconectado")
        else:
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.connection_status.set("Status: Desconectado")

    def create_ssh_client(self, host, user, password, port=22):
        """Cria e retorna um cliente SSH conectado"""
        client = paramiko.SSHClient()
        
        # Usar política personalizada que recebe a janela principal e a porta
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
            
            # Salvar host no histórico
            self.save_host_history(host)
            
            return client
        except paramiko.AuthenticationException:
            messagebox.showerror("Erro", "Autenticação falhou. Verifique suas credenciais.")
            self.host_combo.focus_set()
        except paramiko.SSHException as e:
            messagebox.showerror("Erro", f"Erro na conexão SSH: {str(e)}")
            self.host_combo.focus_set()
        except Exception as e:
            messagebox.showerror("Erro", f"Erro inesperado: {str(e)}")
            self.host_combo.focus_set()
        
        # Em caso de falha, garantir que o botão Conectar fique ativo
        self.root.after(100, lambda: self.connect_btn.config(state=tk.NORMAL))
        return None

    def start_interactive_shell(self):
        """Inicia a sessão interativa"""
        if not self.client:
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
            
        try:
            self.shell = self.client.invoke_shell()
            self.stop_receiver.clear()
            
            # Thread para receber dados do servidor
            self.receiver_thread = threading.Thread(target=self.receive_output, daemon=True)
            self.receiver_thread.start()
            
            self.append_output(f"Sessão interativa iniciada em {self.user_var.get()}@{self.host_var.get()}\n")
            self.append_output("Digite comandos normalmente. Use 'exit' para sair\n\n")
            
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao iniciar sessão: {str(e)}")
            self.host_combo.focus_set()
            self.disconnect()

    def receive_output(self):
        """Recebe a saída do servidor e atualiza a interface"""
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
        """Envia um comando para o servidor"""
        command = self.cmd_var.get().strip()
        if not command:
            return
            
        if not self.shell:
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
            messagebox.showerror("Erro", f"Erro ao enviar comando: {str(e)}")
            self.host_combo.focus_set()
            self.disconnect()

    def stop_interactive_session(self):
        """Encerra a sessão interativa"""
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
        """Executa comandos pré-definidos"""
        if not self.client:
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
        """Executa comandos em segundo plano"""
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
            self.root.after(0, messagebox.showerror, "Erro", f"Falha na execução: {str(e)}")
            self.root.after(0, self.disconnect)
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Erro", f"Erro inesperado: {str(e)}")
            self.root.after(0, self.disconnect)

    def list_processes(self):
        """Lista os processos do servidor"""
        if not self.client:
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
            
        # Limpar treeview
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
            
        threading.Thread(target=self._list_processes, daemon=True).start()

    def _list_processes(self):
        """Obtém a lista de processos em segundo plano"""
        try:
            # Comando para listar todos os processos
            cmd = "ps aux"
            _, stdout, stderr = self.client.exec_command(cmd, timeout=30)
            
            output = stdout.read().decode(errors='ignore').strip()
            error = stderr.read().decode(errors='ignore').strip()
            
            if error:
                self.root.after(0, messagebox.showerror, "Erro", f"Erro ao listar processos: {error}")
                return
                
            # Processar saída
            processes = []
            for line in output.split('\n')[1:]:  # Ignorar cabeçalho
                if line.strip():
                    parts = line.split(maxsplit=10)
                    if len(parts) >= 11:
                        user = parts[0]
                        pid = parts[1]
                        command = parts[10]
                        
                        # Aplicar filtro permanente
                        skip = False
                        
                        # Verificar usuários bloqueados - USANDO COMPARAÇÃO EXATA
                        for blocked_user in self.permanent_filter['users']:
                            # Comparação exata, ignorando case
                            if user.lower() == blocked_user.lower():
                                skip = True
                                break
                        
                        # Verificar comandos bloqueados
                        if not skip and self.permanent_filter['commands']:
                            for blocked_cmd in self.permanent_filter['commands']:
                                if blocked_cmd.lower() in command.lower():
                                    skip = True
                                    break
                        
                        if not skip:
                            processes.append({
                                'user': user,
                                'pid': pid,
                                'idle': parts[9],  # %CPU
                                'command': command
                            })
            
            # Armazenar todos os processos (já pré-filtrados)
            self.all_processes = processes
            
            # Adicionar à treeview
            for proc in self.all_processes:
                self.root.after(0, self.add_process_to_tree, proc)
                
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Erro", f"Falha ao listar processos: {str(e)}")
            self.root.after(0, self.disconnect)
    
    def add_process_to_tree(self, proc):
        """Adiciona um processo à treeview de forma segura"""
        self.process_tree.insert('', tk.END, values=(
            proc['user'], 
            proc['pid'], 
            proc['idle'], 
            proc['command']
        ))

    def kill_pids(self):
        """Derruba os PIDs especificados usando o menu interativo"""
        if not self.client:
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
            
        # Obter PIDs e converter para lista
        pids_input = self.pids_var.get().strip()
        
        if not pids_input:
            messagebox.showwarning("Aviso", "Nenhum PID especificado!")
            return
        
        # Aceitar múltiplos formatos
        pids = []
        for part in re.split(r'[,\s\-]+', pids_input):
            if part.strip():
                pids.append(part.strip())
        
        if not pids:
            messagebox.showwarning("Aviso", "Nenhum PID válido encontrado!")
            return
            
        # Confirmar ação
        confirm_message = (
            f"Tem certeza que deseja derrubar {len(pids)} processo(s)?\n\n"
            f"PIDs: {', '.join(pids)}\n\n"
            "Esta operação usará o menu interativo do sistema."
        )
        
        confirm = messagebox.askyesno("Confirmar Operação", confirm_message)
        
        if not confirm:
            return
            
        # Verificar se a sessão interativa está ativa
        if not self.shell:
            messagebox.showerror("Erro", "Sessão interativa não está ativa!")
            self.host_combo.focus_set()
            return
            
        threading.Thread(
            target=self._kill_pids_interactive, 
            args=(pids,),
            daemon=True
        ).start()

    def _kill_pids_interactive(self, pids):
        """Executa o fluxo interativo para derrubar PIDs"""
        try:
            # Construir sequência de comandos
            pids_str = " ".join(pids)
            sequence = [
                "3",               # Selecionar opção 3
                pids_str,          # Inserir PIDs
                ""                 # Enter final
            ]
            
            # Enviar sequência
            for cmd in sequence:
                if not self.running:
                    return
                self.root.after(0, self.append_output, f">>> Enviando: {cmd}\n")
                self.shell.send(cmd + "\n")
                time.sleep(0.5)
            
            self.root.after(0, self.append_output, "\nComandos enviados. Verifique o terminal.\n")
            
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Erro", f"Erro ao derrubar processos: {str(e)}")
            self.root.after(0, self.disconnect)
    
    def consultar_matricula(self):
        """Consulta processos por matrícula"""
        if not self.client:
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
            
        matricula = self.matricula_var.get().strip()
        # Permitir campo vazio para consultar tudo
        if not matricula:
            matricula = ""
            
        self.matricula_status_var.set(f"Consultando matrícula/romaneio {matricula}...")
        
        # Limpar resultados anteriores
        self.clear_matricula_results()
        self.matricula_pids_var.set("")  # Limpar campo de PIDs
        
        # Iniciar captura de saída
        self.capturing_matricula = True
        self.matricula_output = ""
        
        threading.Thread(
            target=self._consultar_matricula, 
            args=(matricula,),
            daemon=True
        ).start()

    def _consultar_matricula(self, matricula):
        """Executa o fluxo interativo para consultar por matrícula"""
        try:
            # Enviar comandos
            sequence = [
                "2",               # Selecionar opção 2
                "/d/work",         # Informar caminho
                f"*{matricula}",   # Padrão de pesquisa
                ""                 # Enter final
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
            self.root.after(0, messagebox.showerror, "Erro", f"Erro ao consultar matrícula: {str(e)}")
            self.root.after(0, self.matricula_status_var.set, 
                          f"Erro na operação: {str(e)}")
            self.root.after(0, self.disconnect)

    def clear_matricula_results(self):
        """Limpa os resultados anteriores da consulta de matrícula"""
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)

    def process_matricula_output(self, matricula):
        """Processa a saída capturada para extrair os resultados da matrícula"""
        try:
            # Padrão regex para encontrar linhas com USER, PID e NAME
            pattern = r'^(\S+)\s+(\d+)\s+(\S.*)$'
            
            matches = re.findall(pattern, self.matricula_output, re.MULTILINE)
            
            if not matches:
                self.matricula_status_var.set(f"Nenhum processo encontrado para {matricula}")
                return
            
            for match in matches:
                self.result_tree.insert('', tk.END, values=match)
            
            self.matricula_status_var.set(f"Consulta concluída: {len(matches)} processos encontrados")
            
        except Exception as e:
            self.matricula_status_var.set(f"Erro ao processar resultados: {str(e)}")
    
    def derrubar_pid_selecionado(self):
        """Derruba os PIDs selecionados na tabela de resultados da matrícula"""
        if not self.client:
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
            
        # Obter PIDs selecionados na tabela
        selected_items = self.result_tree.selection()
        if not selected_items:
            messagebox.showwarning("Aviso", "Nenhum PID selecionado na tabela!")
            return
            
        pids = []
        for item in selected_items:
            values = self.result_tree.item(item, 'values')
            if len(values) >= 2:  # Garantir que temos pelo menos USER e PID
                pid = values[1]
                pids.append(pid)
                
        if not pids:
            messagebox.showwarning("Aviso", "Nenhum PID válido selecionado!")
            return
            
        # Confirmar ação
        confirm_message = (
            f"Tem certeza que deseja derrubar {len(pids)} processo(s)?\n\n"
            f"PIDs: {', '.join(pids)}\n\n"
            "Esta operação usará o menu interativo do sistema."
        )
        
        confirm = messagebox.askyesno("Confirmar Operação", confirm_message)
        
        if not confirm:
            return
            
        # Verificar se a sessão interativa está ativa
        if not self.shell:
            messagebox.showerror("Erro", "Sessão interativa não está ativa!")
            self.host_combo.focus_set()
            return
            
        threading.Thread(
            target=self._kill_pids_interactive, 
            args=(pids,),
            daemon=True
        ).start()
    
    # ===== FUNÇÕES para a aba "Consultar Tela" =====
    def consultar_tela(self):
        """Consulta processos por tela"""
        if not self.client:
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
            
        tela = self.tela_var.get().strip()
        # Manter o asterisco mesmo com campo vazio
        if not tela:
            tela = "*"
            
        self.tela_status_var.set(f"Consultando tela {tela}...")
        
        # Limpar resultados anteriores
        self.clear_tela_results()
        self.tela_pids_var.set("")  # Limpar campo de PIDs
        
        # Iniciar captura de saída
        self.capturing_tela = True
        self.tela_output = ""
        
        threading.Thread(
            target=self._consultar_tela, 
            args=(tela,),
            daemon=True
        ).start()

    def _consultar_tela(self, tela):
        """Executa o fluxo interativo para consultar por tela"""
        try:
            # Enviar comandos com caminho alterado para /d/dados
            sequence = [
                "2",               # Selecionar opção 2
                "/d/dados",        # Informar caminho (ALTERADO)
                f"*{tela}",        # Padrão de pesquisa
                ""                 # Enter final
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
            self.root.after(0, messagebox.showerror, "Erro", f"Erro ao consultar tela: {str(e)}")
            self.root.after(0, self.tela_status_var.set, 
                          f"Erro na operação: {str(e)}")
            self.root.after(0, self.disconnect)

    def clear_tela_results(self):
        """Limpa os resultados anteriores da consulta de tela"""
        for item in self.tela_tree.get_children():
            self.tela_tree.delete(item)

    def process_tela_output(self, tela):
        """Processa a saída capturada para extrair os resultados da tela"""
        try:
            # Padrão regex para encontrar linhas com USER, PID e NAME
            pattern = r'^(\S+)\s+(\d+)\s+(\S.*)$'
            
            matches = re.findall(pattern, self.tela_output, re.MULTILINE)
            
            if not matches:
                self.tela_status_var.set(f"Nenhum processo encontrado para {tela}")
                return
            
            for match in matches:
                self.tela_tree.insert('', tk.END, values=match)
            
            self.tela_status_var.set(f"Consulta concluída: {len(matches)} processos encontrados")
            
        except Exception as e:
            self.tela_status_var.set(f"Erro ao processar resultados: {str(e)}")
    
    def derrubar_pid_tela(self):
        """Derruba os PIDs selecionados na tabela de resultados da tela"""
        if not self.client:
            messagebox.showerror("Erro", "Não conectado!")
            self.host_combo.focus_set()
            return
            
        # Obter PIDs selecionados na tabela
        selected_items = self.tela_tree.selection()
        if not selected_items:
            messagebox.showwarning("Aviso", "Nenhum PID selecionado na tabela!")
            return
            
        pids = []
        for item in selected_items:
            values = self.tela_tree.item(item, 'values')
            if len(values) >= 2:  # Garantir que temos pelo menos USER e PID
                pid = values[1]
                pids.append(pid)
                
        if not pids:
            messagebox.showwarning("Aviso", "Nenhum PID válido selecionado!")
            return
            
        # Confirmar ação
        confirm_message = (
            f"Tem certeza que deseja derrubar {len(pids)} processo(s)?\n\n"
            f"PIDs: {', '.join(pids)}\n\n"
            "Esta operação usará o menu interativo do sistema."
        )
        
        confirm = messagebox.askyesno("Confirmar Operação", confirm_message)
        
        if not confirm:
            return
            
        # Verificar se a sessão interativa está ativa
        if not self.shell:
            messagebox.showerror("Erro", "Sessão interativa não está ativa!")
            self.host_combo.focus_set()
            return
            
        threading.Thread(
            target=self._kill_pids_interactive, 
            args=(pids,),
            daemon=True
        ).start()

# =================================================================
# SCRIPT DE RELEASE PARA AUTOMATIZAR ATUALIZAÇÕES
# =================================================================
def release_main():
    """Função principal para o script de release"""
    import argparse
    import json
    import re
    import tempfile
    import subprocess
    from datetime import datetime
    
    # Configurações
    REPO_NAME = "seu-repositorio"
    GITHUB_USER = "seu-usuario"
    VERSION_FILE = "version.json"
    MAIN_SCRIPT = "ssh_tool.py"  # Este arquivo
    EXE_NAME = "GerenciadorSSH.exe"
    PYINSTALLER_CMD = [
        "pyinstaller",
        "--onefile",
        "--windowed",
        f"--name={EXE_NAME}",
        "--icon=logoicogrupoprofarma.ico",
        MAIN_SCRIPT
    ]

    def get_current_version():
        """Obtém a versão atual do arquivo principal"""
        version_pattern = re.compile(r'SOFTWARE_VERSION\s*=\s*"(\d+\.\d+\.\d+)"')
        
        with open(MAIN_SCRIPT, 'r', encoding='utf-8') as f:
            for line in f:
                match = version_pattern.search(line)
                if match:
                    return match.group(1)
        return "0.0.0"

    def validate_version_format(version):
        """Valida o formato da versão"""
        if not re.match(r'^\d+\.\d+\.\d+$', version):
            raise ValueError("Formato de versão inválido. Use MAJOR.MINOR.PATCH")
        return version

    def update_version_file(new_version, build_exe=True):
        """Atualiza o arquivo version.json com a nova versão"""
        # Construir URLs para a nova versão
        base_url = f"https://github.com/{GITHUB_USER}/{REPO_NAME}/releases/download/v{new_version}/"
        
        version_data = {
            "version": new_version,
            "release_date": datetime.now().strftime("%Y-%m-%d"),
            "exe_url": base_url + EXE_NAME,
            "py_url": base_url + MAIN_SCRIPT,
            "notes": ""
        }
        
        # Salvar arquivo version.json
        with open(VERSION_FILE, 'w') as f:
            json.dump(version_data, f, indent=4)
        
        print(f"✅ version.json atualizado para v{new_version}")
        
        # Adicionar ao controle de versão
        subprocess.run(["git", "add", VERSION_FILE], check=True)
        subprocess.run(["git", "commit", "-m", f"Atualiza version.json para v{new_version}"], check=True)
        
        if build_exe:
            build_executable()

    def build_executable():
        """Compila o executável usando PyInstaller"""
        print("\n🔨 Compilando executável...")
        try:
            # Construir comando PyInstaller
            cmd = PYINSTALLER_CMD
            
            # Executar compilação
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if "completed successfully" in result.stdout:
                print("✅ Executável compilado com sucesso!")
                return True
            else:
                print("❌ Erro na compilação:")
                print(result.stderr)
                return False
        except subprocess.CalledProcessError as e:
            print(f"❌ Falha na compilação: {e.stderr}")
            return False

    def create_github_release(new_version):
        """Cria uma nova release no GitHub"""
        print("\n🚀 Criando release no GitHub...")
        
        # Tag da versão
        tag_name = f"v{new_version}"
        
        # Mensagem da release
        release_notes = input("✏️ Digite as notas da release: ")
        
        # Construir comando
        cmd = [
            "gh", "release", "create",
            tag_name,
            f"--title=v{new_version}",
            f"--notes={release_notes}",
            f"dist/{EXE_NAME}",
            MAIN_SCRIPT,
            VERSION_FILE
        ]
        
        try:
            subprocess.run(cmd, check=True)
            print(f"✅ Release {tag_name} criada com sucesso!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Falha ao criar release: {e}")
            return False
        return True

    def update_version_in_code(new_version):
        """Atualiza a versão no código-fonte principal"""
        try:
            # Criar arquivo temporário
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
                with open(MAIN_SCRIPT, 'r') as original:
                    for line in original:
                        if line.strip().startswith('SOFTWARE_VERSION'):
                            tmp_file.write(f'SOFTWARE_VERSION = "{new_version}"\n')
                        else:
                            tmp_file.write(line)
                
                temp_name = tmp_file.name
            
            # Substituir arquivo original
            os.replace(temp_name, MAIN_SCRIPT)
            
            print(f"✅ Versão no código atualizada para v{new_version}")
            return True
        except Exception as e:
            print(f"❌ Falha ao atualizar código: {str(e)}")
            return False

    # Configurar parser de argumentos
    parser = argparse.ArgumentParser(
        description='Automatiza releases do Gerenciador SSH',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('version', nargs='?', help='Nova versão no formato MAJOR.MINOR.PATCH')
    parser.add_argument('--only-version', action='store_true', help='Apenas atualiza a versão no código')
    parser.add_argument('--skip-build', action='store_true', help='Pula a compilação do executável')
    
    args = parser.parse_args()
    
    try:
        # Obter/validar versão
        if args.version:
            new_version = validate_version_format(args.version)
        else:
            current = get_current_version()
            parts = [int(x) for x in current.split('.')]
            parts[-1] += 1  # Incrementa o PATCH
            new_version = ".".join(str(x) for x in parts)
            print(f"⚠️  Versão não especificada. Usando versão incrementada: v{new_version}")
        
        # Atualizar versão no código
        if not update_version_in_code(new_version):
            return
        
        if args.only_version:
            print("✨ Apenas versão no código atualizada")
            return
        
        # Atualizar version.json
        update_version_file(new_version, not args.skip_build)
        
        # Criar release no GitHub
        if not args.skip_build:
            create_github_release(new_version)
        
        print("\n🎉 Release completa realizada com sucesso!")
    
    except Exception as e:
        print(f"\n❌ ERRO: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Forçar regeneração do arquivo de configuração se solicitado
    config_path = os.path.join(os.path.expanduser("~"), ".ssh_tool_config")
    if '--reset-config' in sys.argv and os.path.exists(config_path):
        os.unlink(config_path)
    
    # Se o argumento --release for passado, executar o script de release
    if '--release' in sys.argv:
        # Remover o --release para não atrapalhar o parsing
        sys.argv.remove('--release')
        release_main()
    else:
        # Executar a aplicação normalmente
        root = tk.Tk()
        app = SSHClientGUI(root)
        root.mainloop()