import secrets
import os
import pathlib
import base64
import os
import hashlib


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
        return bytes(resultado_xor)
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


# ==========================================
# Letra A
# ==========================================

print(f"{'='*40}")
print(f"PARTE A - TESTES DE CODIFICAÇÃO")
print(f"{'='*40}")



# Salvo os caminhos desta maneira para facilitar (lembrar de colocar sem as pastas para facilitar a reprodutibilidade da fessora)
caminho_arq_txt = "Laboratorio_1/materiais_laboratorio_L1_OTP\materiais_l1_otp\mensagens_teste.txt"
caminho_arq_bin = "Laboratorio_1/materiais_laboratorio_L1_OTP\materiais_l1_otp\pacote_sintetico.bin"


# Leio os arquivos a principio em "r" de modo a pegar ASCII e UTF para realizar os testes
with open(caminho_arq_txt, "r", encoding="utf-8") as f:
    for line in f:
        if "ASCII:" in line:
            texto_ASCII = line.split("ASCII:")[1].strip()
        if "UTF8:" in line:
            texto_UTF = line.split("UTF8:")[1].strip()
print(f"\nM1 ASCII: {texto_ASCII}")
print(f"M2 UTF-8: {texto_UTF}")



# Tranformo de string para bytes de modo a conseguir realizar as operações de XOR
# Além disso tem aquela questão de UTF-8 para caracteres especiais terem mais bytes para representar, logo preciso que a chave seja do tamanho da palavra em bytes e não em string pq são diferentes
texto_ASCII_bytes = texto_ASCII.encode("ascii")
texto_UTF_bytes = texto_UTF.encode("utf-8")

# print(f"\nASCII → {len(texto_ASCII_bytes)} bytes: {texto_ASCII_bytes}")
# print(f"UTF-8 → {len(texto_UTF_bytes)} bytes: {texto_UTF_bytes}")

# Gero duas chaves diferentes, já que é o OTP e por as mensagens terem tamanhos diferentes
chave_ASCII = gerar_chave(len(texto_ASCII_bytes))
chave_UTF = gerar_chave(len(texto_UTF_bytes))

# print(f"\nChave ASCII → {len(chave_ASCII)} bytes: {chave_ASCII.hex()} em hex()")
# print(f"Chave UTF-8 → {len(chave_UTF)} bytes: {chave_UTF.hex()} em hex()")

# Uma vez com as chaves e as mensagens em bytes, consigo usar a função de "cifrar" que criei (vai fazer o XOR bunitin)
cifra_ASCII = cifrar(texto_ASCII_bytes,chave_ASCII)
cifra_UTF = cifrar(texto_UTF_bytes,chave_UTF)

# print(f"\nCifra ASCII → {len(cifra_ASCII)} bytes: {cifra_ASCII.hex()}")
# print(f"Cifra UTF-8 → {len(cifra_UTF)} bytes: {cifra_UTF.hex()}")

# Basta usar o decifrar agora e conseguir recuperar as mensagens
decifrado_ASCII = decifrar(cifra_ASCII, chave_ASCII)
decifrado_UTF = decifrar(cifra_UTF, chave_UTF)

# print(f"\nDecifrado ASCII → {len(decifrado_ASCII)} bytes: {decifrado_ASCII}")
# print(f"Decifrado UTF-8 → {len(decifrado_UTF)} bytes: {decifrado_UTF}")


# Como Exercicio pediu para mostrar tudo em hex:

print("=== ASCII ===")
print(f"  Texto:      {texto_ASCII_bytes.hex()}")
print(f"  Chave:      {chave_ASCII.hex()}")
print(f"  Cifra:      {cifra_ASCII.hex()}")
print(f"  Decifrado:  {decifrado_ASCII.hex()}")
if(texto_ASCII_bytes==decifrado_ASCII):
    print("\nOs texto recuperado ASCII é igual ao texto original ASCII")
else:
    print("\nCaso ASCII não deu igual.")


# Aqui é do UTF-8:
print("\n=== UTF-8 ===")
print(f"  Texto:      {texto_UTF_bytes.hex()}")
print(f"  Chave:      {chave_UTF.hex()}")
print(f"  Cifra:      {cifra_UTF.hex()}")
print(f"  Decifrado:  {decifrado_UTF.hex()}")
if(texto_UTF_bytes==decifrado_UTF):
    print("\nOs texto recuperado UTF-8 é igual ao texto original UTF-8")
else:
    print("\nCaso UTF-8 não deu igual.")



with open(caminho_arq_bin, "rb") as f:
    arquivo_bin = f.read()
# print(f"Arquivo .bin → {len(arquivo_bin)} bytes: {arquivo_bin.hex()}")

chave_bin = gerar_chave(len(arquivo_bin))
# print(f"Chave .bin   → {len(chave_bin)} bytes: {chave_bin.hex()} em hex()")

cifra_bin = cifrar(arquivo_bin, chave_bin)
# print(f"Cifra .bin   → {len(cifra_bin)} bytes: {cifra_bin.hex()}")

decifrado_bin = decifrar(cifra_bin, chave_bin)
print(f"Decifrado    → {len(decifrado_bin)} bytes: {decifrado_bin.hex()}")
print("=== BIN ===")
print(f"  Texto:      {arquivo_bin.hex()}")
print(f"  Chave:      {chave_bin.hex()}")
print(f"  Cifra:      {cifra_bin.hex()}")
print(f"  Decifrado:  {decifrado_bin.hex()}")
if(arquivo_bin==decifrado_bin):
    print("\nO arquivo recuperado .bin é igual ao arquivo original .bin")
else:
    print("\nCaso .bin não deu igual.")



# Acho que era isso a letra A
del texto_ASCII, texto_UTF, texto_ASCII_bytes, texto_UTF_bytes
del chave_ASCII, chave_UTF, cifra_ASCII, cifra_UTF, decifrado_ASCII, decifrado_UTF
del arquivo_bin, chave_bin, cifra_bin, decifrado_bin
print("\nDeletando tudo para começar a B...")


#===========================================
# Letra B
#===========================================
print(f"\n{'='*40}")
print(f"PARTE B - LEITURA,CIFRA E DECIFRA DE ARQUIVO")
print(f"{'='*40}")

# Vou salvar o caminho para facilitar, lembrando de colocar os nomes sem pasta para facilitar a reprodutibilidade
arquivo_entrada = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/registros_rede_sinteticos.csv"
arquivo_chave = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/chave.key"
arquivo_cifrado = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/arquivo.cifrado"
arquivo_recuperado = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/arquivo.recuperado"
arquivo_SHA256 = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/SHA256SUMS.txt"


# Do readme:
# 2. registros_rede_sinteticos.csv
#    Pequeno conjunto de registros fictícios de rede para a Parte B. O arquivo
#    deve ser lido integralmente em modo binário, cifrado e depois recuperado.

# 1. Leitura do arquivo original com "rb" (Read Binary)
with open(arquivo_entrada, "rb") as f:
    dados_originais = f.read()

# 2. Gerar a chave (com o mesmo tamanho do arquivo lido bytes)
chave = gerar_chave(len(dados_originais)) # como meus dados foram lidos em rb eles estão em bytes, com isso gero uma chave deste tamanho


# exercício pede para salvar a chave num arquivo separado.
# 3. Gravar a chave em disco temporariamente com "wb" (Write Binary)
with open(arquivo_chave, "wb") as f:
    f.write(chave)
    del chave # depois de escrever o arquivo chave.key eu deleto o valor da variável durante o códiguin


with open(arquivo_chave, "rb") as f:
    chave_lida_do_arquivo = f.read()

# 4. Cifrar os dados
dados_cifrados = cifrar(dados_originais, chave_lida_do_arquivo) # passo para minha função "cifrar" os meus dados em bytes e minha chave em bytes para ele realizar o xor e gerar a cifra

# exercício pede para gerar o arquivo "arquivo.cifrado"
# 5. Gravar resultados cifrados com "wb"
with open(arquivo_cifrado, "wb") as f:
    f.write(dados_cifrados)

# Releio a partir do arquivo para verificar se deu certin msm
with open(arquivo_cifrado, "rb") as f:
    dados_cifrados_lidos_arquivo = f.read()
    del dados_cifrados

# 6. Decifrar os dados
dados_decifrados = decifrar(dados_cifrados_lidos_arquivo, chave_lida_do_arquivo)

# exercício pede para gerar o arquivo "arquivo.recuperado"
# 7. Gravar resultados recuperados com "wb"
with open(arquivo_recuperado, "wb") as f:
    f.write(dados_decifrados)
    del dados_decifrados

with open(arquivo_recuperado, "rb") as f:
    dados_recuperados_lidos_arquivo = f.read()

# ==========================================
# EXIBIÇÃO DE RESULTADOS E VALIDAÇÕES
# ==========================================

# Registro dos tamanhos exigido no roteiro
print("--- Registro de Tamanhos ---")
print(f"Original:   {len(dados_originais)} bytes")
print(f"Chave:      {len(chave_lida_do_arquivo)} bytes")
print(f"Cifrado:    {len(dados_cifrados_lidos_arquivo)} bytes")
print(f"Recuperado: {len(dados_recuperados_lidos_arquivo)} bytes")

# Verificação Criptográfica com SHA-256
print("\n--- Verificação de Integridade (SHA-256) ---")

# Calculando o hash em cima dos dados que lemos lá no início
hash_original = hashlib.sha256(dados_originais).hexdigest() #hexdigest faz aparecer em hexadecimal ao invés de bytes

# Lendo o arquivo recuperado (dnv para deixar o passo a passo da ideia no código) direto do disco com "rb" para provar que salvou certo
with open(arquivo_recuperado, "rb") as f:
    dados_recuperados_lidos_arquivo = f.read()

hash_recuperado = hashlib.sha256(dados_recuperados_lidos_arquivo).hexdigest()


with open(arquivo_SHA256, "r") as f:
    for linha in f:
        if "registros_rede_sinteticos.csv" in linha:
            arquivo_sha_conferir_txt_prof, _ = linha.split()
            break



print(f"Hash Original arquivo txt:   {arquivo_sha_conferir_txt_prof}")
print(f"Hash Original:               {hash_original}")
print(f"Hash Recuperado:             {hash_recuperado}")

if hash_original == hash_recuperado == arquivo_sha_conferir_txt_prof:
    print("\nSUCESSO: Os hashes coincidem! O arquivo foi cifrado e recuperado com perfeição.")
else:
    print("\nFALHA: Os hashes são diferentes. O arquivo foi corrompido.")

# Remoção da cópia local da chave conforme o aviso
if os.path.exists(arquivo_chave):
    os.remove(arquivo_chave)
    print("\nAviso: O arquivo 'chave.key' foi removido do diretório por segurança.")


# Limpeza das variáveis da Parte B
del arquivo_entrada, arquivo_chave, arquivo_cifrado, arquivo_recuperado, arquivo_SHA256
del dados_originais, chave_lida_do_arquivo, dados_cifrados_lidos_arquivo, dados_recuperados_lidos_arquivo
del hash_original, hash_recuperado, arquivo_sha_conferir_txt_prof
print("\nDeletando tudo para começar a C...")



#===========================================
# Letra C
#===========================================

print(f"\n{'='*40}")
print(f"PARTE C - TWO-TIME PAD")
print(f"{'='*40}")


caminho_msg_test = "Laboratorio_1/materiais_laboratorio_L1_OTP/materiais_l1_otp/mensagens_teste.txt"
with open(caminho_msg_test, "r") as f:
    for line in f:
        if "M1:" in line:
            mensagem_1 = line.split("M1: ")[1].strip() # strip é pq notei um /n doideira...
        if "M2:" in line:
            mensagem_2 = line.split("M2: ")[1].strip()

print("="*40)
print("Número 1: Mostrar C1 ⊕ C2 e M1 ⊕ M2")
print("="*40)
print(f"\nM1: {mensagem_1}")
print(f"M2: {mensagem_2}")

mensagem_1_bytes = mensagem_1.encode('utf-8')
mensagem_2_bytes = mensagem_2.encode('utf-8')

print(f"\nMensagem 1 (bytes): {mensagem_1_bytes}")
print(f"Mensagem 2 (bytes): {mensagem_2_bytes}")
print(f"Mensagem 1 (tamanho em chars): {len(mensagem_1)}")
print(f"Mensagem 1 (tamanho em bytes): {len(mensagem_1_bytes)}")

chave_two_time_pad = gerar_chave(len(mensagem_1_bytes))
print(f"\nChave (bytes): {chave_two_time_pad}")
print(f"Chave (hex):   {chave_two_time_pad.hex()}")
print(f"Chave (tamanho em bytes): {len(chave_two_time_pad)}")

cifra_1 = cifrar(mensagem_1_bytes, chave_two_time_pad) # C1 = M1 ⊕ K
cifra_2 = cifrar(mensagem_2_bytes, chave_two_time_pad) # C2 = M2 ⊕ K

print(f"\nCifra 1 (bytes): {cifra_1}") 
print(f"Cifra 2 (bytes): {cifra_2}")

c1_x_c2 = xor_bytes(cifra_1,cifra_2) # c1_x_c2 = C1 ⊕ C2
M1_x_M2 = xor_bytes(mensagem_1_bytes,mensagem_2_bytes) # M1_x_M2 = M1 ⊕ M2

print(f"\nC1 ⊕ C2 = {c1_x_c2}")
print(f"M1 ⊕ M2 = {M1_x_M2}")

if(c1_x_c2==M1_x_M2):
    print("\nSim! Os valores de C1 ⊕ C2 e M1 ⊕ M2 são iguais. Falha pelo Two Time Pad...")
else:
    print("\nNão! Eles não são iguais.")


# C1 ⊕ C2 = (M1 ⊕ K) ⊕ (M2 ⊕ K)
#          = M1 ⊕ M2 ⊕ K ⊕ K
#          = M1 ⊕ M2 ⊕ 0
#          = M1 ⊕ M2


print("="*40)
print("Número 2: Ataque supondo saber C1 M1 achar K")
print("="*40)

chave_reencontrada_ataq = xor_bytes(mensagem_1_bytes,cifra_1) # K = M1 ⊕ C1

print(f"\nChave criada pelo sistema:                           {chave_two_time_pad}")
print(f"Chave descoberta pelo atacante por conhecer M1 e C1:   {chave_reencontrada_ataq}")

if(chave_reencontrada_ataq==chave_two_time_pad):
    print("\nSim! O valor da Chave criada pelo sistema é igual ao valor da Chave obtida pelo ataque. Tudo pelo atacante conhecer M1 e C1... Problemão em")
else:
    print("\nNão! Elas não são iguais.")

# M1 ⊕ C1 = M1 ⊕ M1 ⊕ K
#          = (M1 ⊕ M1) ⊕ K
#          = K

print("="*40)
print("Número 3: Ataque supondo saber C2 e K recuperado para achar M2")
print("="*40)

mensagem_2_recuperada_atacante_chave_recuperada = xor_bytes(cifra_2, chave_reencontrada_ataq)

print(f"M2 recuperada pelo atacante: {mensagem_2_recuperada_atacante_chave_recuperada}")
print(f"M2 original:                 {mensagem_2_bytes}")


if(mensagem_2_recuperada_atacante_chave_recuperada==mensagem_2_bytes):
    print("Sim! O atacante, infelizmente, conseguiu recuperar a mensagem 2 a partir da K obtida no ataque anterior e a cifra 2 interceptada... Vish")
else:
    print("Não! Elas não são iguais.")


# C2 ⊕ K = M2 ⊕ K ⊕ K
#         = M2 ⊕ (K ⊕ K)
#         = M2



# como to deletando tudo a cada letra refaço:
# caminho_msg_test = "materiais_laboratorio_L1_OTP/materiais_l1_otp/mensagens_teste.txt"
# with open(caminho_msg_test, "r") as f:
#     for line in f:
#         if "M1:" in line:
#             mensagem_1 = line.split("M1: ")[1].strip() # strip é pq notei um /n doideira...
#         if "M2:" in line:
#             mensagem_2 = line.split("M2: ")[1].strip()
        
# print(mensagem_1)
# print(mensagem_2) # ja tenho essas variaveis


# mensagem_1_bytes = mensagem_1.encode('utf-8')
# mensagem_2_bytes = mensagem_2.encode('utf-8')
# ja tenho essas variaveis no notebook eu tava só deixando bonito.

# print(f"Mensagem 1 (bytes): {mensagem_1_bytes}")
# print(f"Mensagem 2 (bytes): {mensagem_2_bytes}")
# print(f"Mensagem 1 (tamanho em chars): {len(mensagem_1)}")
# print(f"Mensagem 1 (tamanho em bytes): {len(mensagem_1_bytes)}")

print("="*40)
print("Número 5 Testando K1 e K2 diferentes. Validar One Time Pad é forte")
print("="*40)

chave_k1 = gerar_chave(len(mensagem_1_bytes))
chave_k2 = gerar_chave(len(mensagem_2_bytes))
print(f"\nChave K1 (bytes): {chave_k1}")
print(f"Chave K1 (tamanho em bytes): {len(chave_k1)}")
print(f"Chave K2 (bytes): {chave_k2}")
print(f"Chave K2 (tamanho em bytes): {len(chave_k2)}")


cifra_1_chave1 = cifrar(mensagem_1_bytes, chave_k1) # C1 = M1 ⊕ K1
cifra_2_chave2 = cifrar(mensagem_2_bytes, chave_k2) # C2 = M2 ⊕ K2

print(f"\nCifra 1 (bytes): {cifra_1_chave1}") 
print(f"Cifra 2 (bytes): {cifra_2_chave2}")


c1_x_c2 = xor_bytes(cifra_1_chave1,cifra_2_chave2) # c1_x_c2 = C1 ⊕ C2
M1_x_M2 = xor_bytes(mensagem_1_bytes,mensagem_2_bytes) # M1_x_M2 = M1 ⊕ M2

print(f"\nC1 ⊕ C2 = {c1_x_c2}")
print(f"M1 ⊕ M2 = {M1_x_M2}")

if(c1_x_c2==M1_x_M2):
    print("\nSim! Os valores de C1 ⊕ C2 e M1 ⊕ M2 são iguais. Falha pelo Two Time Pad...")
else:
    print("\nNão! Eles não são iguais.")


# C1 ⊕ C2 = (M1 ⊕ K1) ⊕ (M2 ⊕ K2)
#          = M1 ⊕ M2 ⊕ K1 ⊕ K2
#          = Consigo fazer nada...


# Esse ataque é com M1 ⊕ C1 para obter K1, por isso falha. Como para a M2 já tenho outra chave K2 o ataque falhará em C2.

chave_reencontrada_ataq_1 = xor_bytes(mensagem_1_bytes,cifra_1_chave1) # K1 = M1 ⊕ C1
# chave_reencontrada_ataq_2 = xor_bytes(mensagem_2_bytes,cifra_2_chave2) # K2 = M2 ⊕ C2

print(f"\nChave criada pelo sistema:                           {chave_k1}")
print(f"Chave descoberta pelo atacante por conhecer M1 e C1: {chave_reencontrada_ataq_1}")
# print(f"Chave criada pelo sistema:                           {chave_k2}")
# print(f"Chave descoberta pelo atacante por conhecer M1 e C1: {chave_reencontrada_ataq_2}")

if(chave_reencontrada_ataq_1==chave_k1):
    print("\nSim! O valor da Chave criada pelo sistema é igual ao valor da Chave obtida pelo ataque. Tudo pelo atacante conhecer M1 e C1... Será um problema para M2 ?")
else:
    print("\nNão! Elas não são iguais.")

# M1 ⊕ C1 = M1 ⊕ M1 ⊕ K1
#          = (M1 ⊕ M1) ⊕ K1
#          = K1



mensagem_2_recuperada_atacante_chave_recuperada = xor_bytes(cifra_2_chave2, chave_reencontrada_ataq_1)

print(f"\nM2 recuperada pelo atacante: {mensagem_2_recuperada_atacante_chave_recuperada}")
print(f"M2 original:                 {mensagem_2_bytes}")


if(mensagem_2_recuperada_atacante_chave_recuperada==mensagem_2_bytes):
    print("\nSim! O atacante, infelizmente, conseguiu recuperar a mensagem 2 a partir da K obtida no ataque anterior e a cifra 2 interceptada... Vish")
else:
    print("\nNão! Elas não são iguais. Ele obteve só um lixo de bytes ali...")


# C2 ⊕ K1 = M2 ⊕ K2 ⊕ K1
#         = Não consigo fazer nada ... Chaves são diferentes ...

# Limpeza das variáveis da Parte C
del caminho_msg_test, mensagem_1, mensagem_2
del mensagem_1_bytes, mensagem_2_bytes
del chave_two_time_pad, cifra_1, cifra_2
del c1_x_c2, M1_x_M2
del chave_reencontrada_ataq, mensagem_2_recuperada_atacante_chave_recuperada
del chave_k1, chave_k2, cifra_1_chave1, cifra_2_chave2
del chave_reencontrada_ataq_1
print("\nDeletando tudo da Parte C... Fim do script!")

