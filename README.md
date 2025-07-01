# SSH_Avancado_Cobol

Ferramenta com interface gráfica para administração remota de sistemas Cobol via SSH.

## Histórico de Versões

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
- **Listagem de Processos**: Visualize e filtre processos ativos, com bloqueio automático de usuários críticos.
- **Derrubar Processos**: Selecione e derrube PIDs manualmente ou pela tabela.
- **Consulta por Matrícula/Romaneio**: Busque processos relacionados a matrículas ou romaneios em `/d/work`.
- **Consulta por Tela**: Busque processos por número de tela ou romaneio em `/d/dados`.
- **Terminal Interativo**: Execute comandos em tempo real no servidor, com saída contínua.
- **Execução de Comandos em Lote**: Execute múltiplos comandos de uma vez, com resultados exibidos em painel dedicado.
- **Administração**: Configure filtros permanentes de usuários/comandos e altere senhas administrativas.
- **Login Google OAuth**: Autenticação de administradores via conta Google e domínio autorizado.
- **Atualizações Automáticas**: Verifique e baixe novas versões diretamente pelo sistema.
- **Ajuda Integrada**: Manual de uso acessível pelo botão "Ajuda".

## Como usar

1. Execute o arquivo `Cobol_Python_***_Final.py` com Python 3.
2. Preencha os campos de conexão e clique em "Conectar".
3. Navegue pelas abas para acessar as funcionalidades.
4. Use o botão "Administrador" para configurar filtros, senhas e autenticação Google.
5. Clique em "Verificar Atualizações" para buscar novas versões.

## Requisitos

- Python 3.x
- Bibliotecas: `paramiko`, `tkinter`, `Pillow`, `google-auth-oauthlib`, etc.

## Contato

- WhatsApp: 31 99363-9500
- LinkedIn: [Franklin Tadeu](https://www.linkedin.com/in/franklintadeu/)

---

Para detalhes completos das funcionalidades, consulte o código-fonte em [Cobol_Python_v10_Final.py](Cobol_Python_v10_Final.py).
