# SSH_Avancado_Cobol

Ferramenta com interface gráfica para administração remota de sistemas Cobol via SSH.

## Histórico de Versões

- **1.2.9**  
  - **Sistema de autoatualização completo** com verificação de integridade via SHA256  
  - **Geração de executável `.exe` personalizada** com filtros e ícone incluídos  
  - **Interface aprimorada** com ícones, atalhos e feedback visual refinado  
  - **Melhorias de segurança**: criptografia reforçada, verificação de host key interativa  
  - **Ajuda integrada expandida** com manual completo e instruções detalhadas  
  - **Melhorias na administração**: configuração de senhas, filtros e URL de atualização via interface  
  - **Correções de bugs** e melhorias de estabilidade em todas as abas

- **1.2.4**  
  - Correções de problemas de criptografia e segurança de senhas administrativas  
  - Melhoria na verificação e armazenamento de host keys SSH  
  - Interface aprimorada: novas cores, botões e experiência visual  
  - Filtros permanentes e voláteis mais flexíveis para usuários e comandos  
  - Atualização automática aprimorada e configuração de URL via interface  
  - Ajustes em consultas por tela, matrícula e derrubada de processos  
  - Ajuda integrada expandida  
  - Diversas correções de bugs e melhorias de estabilidade

- **1.2.0**  
  - Integração com login Google OAuth para autenticação de administradores  
  - Melhorias de segurança e validação de domínio autorizado  
  - Ajustes na interface para exibição de status de conexão  
  - Correções em consultas por tela e matrícula  
  - Otimização do processo de atualização automática

- **1.1.0**  
  - Melhorias na interface gráfica  
  - Filtros permanentes de usuários e comandos  
  - Atualização automática via URL configurável  
  - Correções de bugs e melhorias de estabilidade

- **1.0.0**  
  - Primeira versão estável  
  - Listagem e derrubada de processos  
  - Consulta por matrícula, tela e terminal interativo  
  - Execução de comandos em lote

## Funcionalidades

- **Conexão SSH**: Conecte-se a servidores informando host, usuário, senha e porta.
- **Listagem de Processos**: Visualize e filtre processos ativos, com bloqueio automático de usuários críticos e comandos sensíveis.
- **Derrubar Processos**: Selecione e derrube PIDs manualmente ou pela tabela, com confirmação interativa.
- **Consulta por Matrícula/Romaneio**: Busque processos relacionados a matrículas ou romaneios em `/d/work`.
- **Consulta por Tela**: Busque processos por número de tela em `/d/dados`, com suporte a filtros e seleção múltipla.
- **Terminal Interativo**: Execute comandos em tempo real no servidor, com saída contínua e sessão interativa.
- **Execução de Comandos em Lote**: Execute múltiplos comandos de uma vez, com resultados exibidos em painel dedicado.
- **Administração**: Configure filtros permanentes de usuários/comandos e altere senhas administrativas e master via interface.
- **Atualizações Automáticas**: Verifique e baixe novas versões diretamente pelo sistema, com verificação de integridade e reinício automático.
- **Geração de Executável**: Crie um `.exe` personalizado com filtros e ícone, diretamente pela interface (acesso master).
- **Ajuda Integrada**: Manual completo acessível pelo botão "Ajuda", com instruções detalhadas.
- **Histórico de Hosts**: Hosts conectados são salvos e sugeridos automaticamente.
- **Segurança Avançada**: Senhas administrativas criptografadas, verificação de host key interativa, e proteção contra comandos perigosos.
- **Interface Moderna**: Visual renovado, ícones, botões coloridos, atalhos de teclado (Ctrl+A, Enter), e feedback visual aprimorado.
- **Compatibilidade Windows**: Ocultação automática do console ao rodar como executável.

## Como usar

1. Execute o arquivo `Cobol_Python_v1.2.9_Final.py` com Python 3.
2. Preencha os campos de conexão e clique em "Conectar".
3. Navegue pelas abas para acessar as funcionalidades.
4. Use o botão "Administrador" para configurar filtros, senhas e URL de atualização.
5. Clique em "Verificar Atualizações" para buscar novas versões.
6. Clique em "Gerar Executável" (modo master) para criar um `.exe` personalizado.
7. Consulte o botão "Ajuda" para instruções detalhadas de uso.

## Requisitos

- Python 3.x
- Bibliotecas: `paramiko`, `tkinter`, `Pillow`, `cryptography`, `packaging`, `PyInstaller`, etc.

## Contato

- WhatsApp: 31 99363-9500  
- LinkedIn: [Franklin Tadeu](https://www.linkedin.com/in/franklintadeu/)
