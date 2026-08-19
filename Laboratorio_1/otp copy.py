import secrets
import os
import pathlib
import base64

# ==========================================
# Letra A
# ==========================================


def gerar_chave(tamanho: int) -> bytes:
    """Gera uma chave criptograficamente segura com tamanho bytes."""
    chave_gerada_aleatoriamente = secrets.token_bytes(tamanho)
    return chave_gerada_aleatoriamente

def xor_bytes(dados: bytes, chave: bytes) -> bytes:
    """Calcula o XOR entre sequencias de mesmo comprimento."""
    if(len(dados)==len(chave)):
        # resultado_xor = bytearray()
        resultado_xor = []
        for i in range(len(dados)):
            resultado_xor.append(dados[i]^chave[i]) 
        return bytes(resultado_xor) #melhor deixar a conversão de bytes aqui já e resolver mais bunitinho do que antes
    else:
        raise ValueError("Erro! Tamanhos diferentes entre dados e chave!")


def cifrar(mensagem: bytes, chave: bytes) -> bytes:
    """Cifra mensagem usando OTP."""
    if(len(mensagem)==len(chave)):
        cifrado_calculado = xor_bytes(mensagem,chave)
        return cifrado_calculado
    else:
        raise ValueError("Erro! Tamanhos diferentes entre mensagem e chave!")

def decifrar(cifrado: bytes, chave: bytes) -> bytes:
    """Decifra um texto cifrado usando OTP."""
    if(len(cifrado)==len(chave)):
        mensagem_decifrada = xor_bytes(cifrado,chave)
        return mensagem_decifrada
    else:
        raise ValueError("Erro! Tamanhos diferentes entre cifrado e chave!")


print("="*40)
print(" PARTE A - TESTES DE CODIFICAÇÃO")
print("="*40)

# --- TESTE 1: Texto sem acentos (ASCII) ---
print("\n[ TESTE 1: ASCII ]")
msg_ascii = "Esta e uma mensagem de teste que nao contem nenhum acento ou caractere especial. Vasco da gama."
msg_bytes_ascii = msg_ascii.encode('utf-8')

chave_ascii = gerar_chave(len(msg_bytes_ascii))
cifrado_ascii = cifrar(msg_bytes_ascii, chave_ascii)
recuperado_ascii = decifrar(cifrado_ascii, chave_ascii)

print("--- Apresentação em Hexadecimal ---")
print(f"Mensagem Original: {msg_bytes_ascii.hex()}")
print(f"Chave Utilizada:   {chave_ascii.hex()}")
print(f"Mensagem Cifrada:  {cifrado_ascii.hex()}")

if msg_bytes_ascii == recuperado_ascii:
    print("Verificação: SUCESSO! Mensagem ASCII recuperada perfeitamente.")


# --- TESTE 2: Texto com acentos (UTF-8) ---
print("\n[ TESTE 2: UTF-8 ]")
msg_utf = "A criptografia do laboratório protegerá nossos dados confidenciais! Vasco da gama!"
msg_bytes_utf = msg_utf.encode('utf-8')

chave_utf = gerar_chave(len(msg_bytes_utf))
cifrado_utf = cifrar(msg_bytes_utf, chave_utf)
recuperado_utf = decifrar(cifrado_utf, chave_utf)

print("--- Apresentação em Hexadecimal ---")
print(f"Mensagem Original: {msg_bytes_utf.hex()}")
print(f"Chave Utilizada:   {chave_utf.hex()}")
print(f"Mensagem Cifrada:  {cifrado_utf.hex()}")

if msg_bytes_utf == recuperado_utf:
    print("Verificação: SUCESSO! Mensagem UTF-8 recuperada perfeitamente.")


# --- TESTE 3: Arquivo Sintético Binário ---
print("\n[ TESTE 3: Binário Sintético ]")
msg_binaria = secrets.token_bytes(50) # Falso arquivo de 50 bytes

chave_binaria = gerar_chave(len(msg_binaria))
cifrado_binario = cifrar(msg_binaria, chave_binaria)
recuperado_binario = decifrar(cifrado_binario, chave_binaria)

print("--- Apresentação em Hexadecimal ---")
print(f"Mensagem Original: {msg_binaria.hex()}")
print(f"Chave Utilizada:   {chave_binaria.hex()}")
print(f"Mensagem Cifrada:  {cifrado_binario.hex()}")

if msg_binaria == recuperado_binario:
    print("Verificação: SUCESSO! Sequência binária recuperada perfeitamente.")

# ==========================================
# Letra B
# ==========================================

import os
import hashlib

# Nomes dos arquivos de trabalho
arquivo_entrada = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/registros_rede_sinteticos.csv"
arquivo_chave = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/chave.key"
arquivo_cifrado = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/arquivo.cifrado"
arquivo_recuperado = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/arquivo.recuperado"

# 1. Leitura do arquivo original com "rb" (Read Binary)
with open(arquivo_entrada, "rb") as f:
    dados_originais = f.read()

# 2. Gerar a chave (com o mesmo tamanho do arquivo lido)
chave = gerar_chave(len(dados_originais))

# 3. Gravar a chave em disco temporariamente com "wb" (Write Binary)
with open(arquivo_chave, "wb") as f:
    f.write(chave)

# 4. Cifrar os dados
dados_cifrados = cifrar(dados_originais, chave)

# 5. Gravar resultados cifrados com "wb"
with open(arquivo_cifrado, "wb") as f:
    f.write(dados_cifrados)

# 6. Decifrar os dados
dados_decifrados = decifrar(dados_cifrados, chave)

# 7. Gravar resultados recuperados com "wb"
with open(arquivo_recuperado, "wb") as f:
    f.write(dados_decifrados)


# ==========================================
# EXIBIÇÃO DE RESULTADOS E VALIDAÇÕES
# ==========================================

# Registro dos tamanhos exigido no roteiro
print("--- Registro de Tamanhos ---")
print(f"Original:   {len(dados_originais)} bytes")
print(f"Cifrado:    {len(dados_cifrados)} bytes")
print(f"Recuperado: {len(dados_decifrados)} bytes")

# Verificação Criptográfica com SHA-256
print("\n--- Verificação de Integridade (SHA-256) ---")

# Calculando o hash em cima dos dados que lemos lá no início
hash_original = hashlib.sha256(dados_originais).hexdigest()

# Lendo o arquivo recuperado direto do disco com "rb" para provar que salvou certo
with open(arquivo_recuperado, "rb") as f:
    dados_lidos_do_disco = f.read()

hash_recuperado = hashlib.sha256(dados_lidos_do_disco).hexdigest()

print(f"Hash Original:   {hash_original}")
print(f"Hash Recuperado: {hash_recuperado}")

if hash_original == hash_recuperado:
    print("\nSUCESSO: Os hashes coincidem! O arquivo foi cifrado e recuperado com perfeição.")
else:
    print("\nFALHA: Os hashes são diferentes. O arquivo foi corrompido.")

# Remoção da cópia local da chave conforme o aviso
if os.path.exists(arquivo_chave):
    os.remove(arquivo_chave)
    print("\nAviso: O arquivo 'chave.key' foi removido do diretório por segurança.")



# ==========================================
# Letra C
# ==========================================

# ==========================================
# PREPARAÇÃO DO AMBIENTE
# ==========================================
tamanho_msg = 32 # Tamanho igual para ambas as mensagens

# "Crie duas mensagens sintéticas M1 e M2 com o mesmo comprimento"
M1 = secrets.token_bytes(tamanho_msg)
M2 = secrets.token_bytes(tamanho_msg)

# "Gere uma única chave K e, deliberadamente, reutilize-a"
K = gerar_chave(tamanho_msg)

# Cifrando com a MESMA chave
C1 = cifrar(M1, K)
C2 = cifrar(M2, K)

print("--- Parte C: Falha Crítica (Reuso de Chave) ---\n")

# ==========================================
# PASSO 1: Calcule C1 ⊕ C2 e confirme que é igual a M1 ⊕ M2
# ==========================================
# A propriedade mágica do XOR: se você fizer XOR de dois textos cifrados com a mesma chave, 
# a chave se anula e o resultado é o XOR das mensagens originais!
xor_cifrados = xor_bytes(C1, C2)
xor_originais = xor_bytes(M1, M2)

if xor_cifrados == xor_originais:
    print("PASSO 1 [SUCESSO]: Confirmado! C1 ⊕ C2 é exatamente igual a M1 ⊕ M2.")

# ==========================================
# PASSO 2: Assuma que o atacante conhece M1 e C1 e recupere a chave
# ==========================================
# Se o hacker sabe o que estava escrito em M1 (por exemplo, um cabeçalho padrão de rede) 
# e tem o texto cifrado C1, ele acha a chave na hora.
K_recuperada_pelo_hacker = xor_bytes(M1, C1)

if K_recuperada_pelo_hacker == K:
    print("PASSO 2 [SUCESSO]: O atacante recuperou a chave original K perfeitamente!")

# ==========================================
# PASSO 3: Use a chave recuperada para obter M2 a partir de C2
# ==========================================
# Agora que o hacker tem a chave, ele lê a segunda mensagem que deveria ser secreta.
M2_recuperada_pelo_hacker = xor_bytes(C2, K_recuperada_pelo_hacker)

if M2_recuperada_pelo_hacker == M2:
    print("PASSO 3 [SUCESSO]: O atacante decifrou M2 com sucesso usando a chave roubada.")

# ==========================================
# PASSO 5: Repita o teste com chaves independentes
# ==========================================
print("\n--- Teste com Chaves Independentes (O jeito certo) ---")
K1_independente = gerar_chave(tamanho_msg)
K2_independente = gerar_chave(tamanho_msg)

# Cifrando corretamente, cada mensagem com sua própria chave
C1_seguro = cifrar(M1, K1_independente)
C2_seguro = cifrar(M2, K2_independente)

# O atacante tenta o mesmo truque do Passo 2
chave_falsa_recuperada = xor_bytes(M1, C1_seguro) # Ele recuperou K1

# O atacante tenta ler M2 usando K1 (Passo 3)
tentativa_de_ler_M2 = xor_bytes(C2_seguro, chave_falsa_recuperada)

if tentativa_de_ler_M2 != M2:
    print("PASSO 5 [SUCESSO]: A invasão falhou! Como as chaves eram independentes, o hacker obteve apenas lixo numérico ao tentar decifrar M2.")