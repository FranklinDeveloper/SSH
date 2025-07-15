# Gerenciador SSH Avan�ado v1.2.13

<<<<<<< HEAD
Ferramenta para gerenciamento de conex�es SSH e processos remotos.
=======
Ferramenta com interface gráfica para administração remota de sistemas Cobol via SSH.

## Histórico de Versões

- **1.2.13** (15/07/2025)  
  - Verificação reforçada do caminho do executável após a compilação  
  - Busca alternativa por qualquer arquivo `.exe` na pasta `dist`  
  - Mensagens de erro detalhadas com caminho do log de erros  
  - Geração de log de compilação para diagnóstico  
  - Desabilitação do botão "Gerar Executável" durante o processo  
  - Reabilitação do botão após conclusão (sucesso ou erro)  
  - Prevenção contra cliques múltiplos durante a compilação  
  - Lógica aprimorada para substituir os filtros padrão  
  - Controle preciso das seções sendo substituídas  
  - Tratamento correto de fechamento de listas  
  - Diálogos de erro mais informativos  
  - Barra de progresso mais precisa  
  - Feedback visual durante todo o processo  
  - Limpeza adequada de recursos temporários  
  - Tratamento de exceções aprimorado  
  - Verificação de dependências (PyInstaller)  
  - Geração de checksum SHA256 para validação  
  - Documentação automática (README.md)

- **1.2.12** (10/07/2025)  
  - Sistema completo de atualização via GitHub com verificação de releases  
  - Geração automática de arquivos de versão/verificação ao criar executável  
  - Novos arquivos suportados: `version.json`, `README.md` e `.sha256`  
  - Validação reforçada com checksum SHA256 para downloads  
  - Melhorias na interface de geração de executável  
  - Correções de segurança na política de host keys

- **1.2.11** (07/07/2025)  
  - Correções de segurança na criptografia  
  - Melhoria no sistema de auto-atualização  
  - Otimização de desempenho na listagem de processos  
  - Correção de bugs na interface administrativa  
  - Novos filtros padrão para comandos bloqueados

- **1.2.9**  
  - Sistema de autoatualização completo com verificação de integridade via SHA256  
  - Geração de executável `.exe` personalizada com filtros e ícone incluídos  
  - Interface aprimorada com ícones, atalhos e feedback visual refinado  
  - Melhorias de segurança: criptografia reforçada, verificação de host key interativa  
  - Ajuda integrada expandida com manual completo e instruções detalhadas  
  - Melhorias na administração: configuração de senhas, filtros e URL de atualização via interface  
  - Correções de bugs e melhorias de estabilidade em todas as abas

## Funcionalidades

### Conexão e Gerenciamento SSH
- **Conexão segura** com autenticação por usuário/senha
- **Histórico de hosts** conectados automaticamente salvo
- **Verificação interativa** de host keys com fingerprint SHA256
- **Terminal interativo** em tempo real com saída contínua

### Administração de Processos
- **Listagem avançada de processos** com filtros permanentes
- **Derrubada seletiva de PIDs** por seleção ou entrada manual
- **Consulta por matrícula/romaneio** em `/d/work`
- **Consulta por tela** em `/d/dados` com suporte a wildcards
- **Filtros dinâmicos** por usuário, PID e comando

### Sistema de Atualização
- **Verificação automática** de novas versões no GitHub
- **Download seguro** com progresso em tempo real
- **Validação de integridade** via SHA256
- **Substituição automática** do executável com reinício

### Ferramentas de Desenvolvimento
- **Geração de executável** (.exe) com ícone personalizado
- **Criação automática de**:
  - `version.json` com metadados da versão
  - Arquivo `.sha256` para verificação de integridade
  - `README.md` básico com instruções
- **Atualização de filtros** embutidos no executável gerado

### Segurança e Administração
- **Configuração de filtros permanentes** para usuários/comandos
- **Criptografia AES-256 + HMAC** para senhas administrativas
- **Duplo nível de acesso**: Admin e Admin Master
- **Política de host keys** com opção de armazenamento permanente
>>>>>>> 73b06fb1e3e4325beb76f1e8d5f8f0e0f26f7036

## Como usar
1. Execute o arquivo `GerenciadorSSH_{SOFTWARE_VERSION}.exe`
2. Preencha os dados de conex�o SSH
3. Utilize as diversas funcionalidades dispon�veis nas abas

<<<<<<< HEAD
**SHA256 Checksum**: `3a57c0d2540d9e80915b2fdcfa1a1c4ccfbc1579a9aae3b8f1682d6e944938fa`
=======
### Conexão Básica
1. Preencha host, usuário, senha e porta
2. Clique em "Conectar" ou pressione Enter
3. Navegue pelas abas para as operações desejadas

### Geração de Executável (Admin Master)
1. Acesse "Administrador" > "Administrador Master"
2. Insira a senha master
3. Clique em "Gerar Executável"
4. Selecione a pasta de destino
5. Os arquivos serão criados:
   - `GerenciadorSSH_X.X.X.exe`
   - `version.json`
   - `GerenciadorSSH_X.X.X.exe.sha256`
   - `README.md`

### Atualização via GitHub
1. Publicar na release do GitHub:
   - Executável principal (.exe)
   - Arquivo .sha256 correspondente
   - version.json atualizado
2. O cliente verificará automaticamente na próxima execução

### Fluxo de Atualização do Cliente
```mermaid
graph TD
    A[Cliente v1.2.12] --> B{Verifica GitHub}
    B -->|Nova versão| C[Baixa executável]
    B -->|Mesma versão| D[Operação normal]
    C --> E[Valida SHA256]
    E -->|Sucesso| F[Substitui executável]
    E -->|Falha| G[Aborta atualização]
    F --> H[Reinicia aplicação]
>>>>>>> 73b06fb1e3e4325beb76f1e8d5f8f0e0f26f7036
