import os
import sys
import pefile
import shutil
import tempfile

def normalize_pe(exe_path):
    try:
        exe_path = os.path.abspath(exe_path)
        print(f"Normalizando: {exe_path}")
        
        if not os.path.exists(exe_path):
            print(f"ERRO: Arquivo não encontrado: {exe_path}")
            sys.exit(1)
            
        # Criar arquivo temporário com nome curto
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as temp_file:
            temp_path = temp_file.name
        
        # Copiar executável para o arquivo temporário
        shutil.copy2(exe_path, temp_path)
        
        # Processar a cópia
        pe = pefile.PE(temp_path)
        pe.OPTIONAL_HEADER.CheckSum = 0
        
        # Escrever modificações
        pe.write(temp_path)
        pe.close()
        
        # Substituir o original
        shutil.move(temp_path, exe_path)
        print("Normalização concluída com sucesso!")
        
    except Exception as e:
        print(f"ERRO na normalização: {str(e)}")
        # Limpar arquivo temporário se existir
        if os.path.exists(temp_path):
            os.remove(temp_path)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: normalize_exe.py <caminho_do_executável>")
        sys.exit(1)
    
    normalize_pe(sys.argv[1])