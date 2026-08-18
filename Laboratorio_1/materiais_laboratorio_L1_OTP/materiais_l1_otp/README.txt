LABORATÓRIO L1 — ONE-TIME PAD DE SHANNON
Disciplina de Cibersegurança — 2026.2

Este pacote contém apenas dados sintéticos. Nenhum endereço, usuário,
identificador ou evento corresponde a uma rede real.

ARQUIVOS DE ENTRADA

1. mensagens_teste.txt
   Mensagens para os testes básicos de codificação ASCII e UTF-8.
   As linhas identificadas como M1 e M2 têm o mesmo tamanho em bytes e podem
   ser usadas na demonstração controlada do reuso de chave.

2. registros_rede_sinteticos.csv
   Pequeno conjunto de registros fictícios de rede para a Parte B. O arquivo
   deve ser lido integralmente em modo binário, cifrado e depois recuperado.

3. pacote_sintetico.bin
   Entrada binária de 256 bytes para confirmar que a implementação não depende
   de texto nem de codificação de caracteres.

4. SHA256SUMS.txt
   Resumos SHA-256 dos três arquivos de entrada. Após a decifração, o resumo do
   arquivo recuperado deve coincidir com o resumo do original.

USO SUGERIDO

- Não altere os arquivos de entrada antes dos testes.
- Abra os arquivos para cifração com o modo "rb" e grave resultados com "wb".
- Gere uma chave nova e independente para cada arquivo ou mensagem.
- A chave deve ter exatamente o mesmo número de bytes do conteúdo cifrado.
- O reuso deliberado de uma chave é permitido somente na Parte C do laboratório.
- Não inclua os arquivos de chave na entrega final.

EXEMPLO DE VERIFICAÇÃO EM PYTHON

    from pathlib import Path
    import hashlib

    dados = Path("registros_rede_sinteticos.csv").read_bytes()
    print(len(dados), hashlib.sha256(dados).hexdigest())

Para validar o resultado, repita o cálculo com o arquivo recuperado e compare
os dois valores.

