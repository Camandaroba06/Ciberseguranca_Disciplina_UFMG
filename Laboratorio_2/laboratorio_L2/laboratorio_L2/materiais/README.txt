LABORATÓRIO L2 — CRIPTOGRAFIA ASSIMÉTRICA
Disciplina de Cibersegurança — 2026.2

Todos os arquivos e identidades deste pacote são sintéticos.

PREPARAÇÃO

Python local:
  python3 -m venv .venv
  source .venv/bin/activate       # Linux/macOS
  python -m pip install -r requirements.txt

Google Colab:
  !pip install "cryptography>=43.0,<47.0"

ARQUIVOS

- codigo_base_l2.py: esqueleto a ser completado pelo estudante.
- mensagem_confidencial.json: entrada textual para cifração híbrida.
- dados_binarios.bin: entrada binária sintética com 1024 bytes.
- comunicado_assinado.txt: mensagem cuja assinatura deve ser verificada.
- comunicado_assinado.sig: assinatura binária RSA-PSS/SHA-256.
- chave_publica_docente.pem: chave pública didática para a verificação.
- SHA256SUMS.txt: resumos dos arquivos de entrada.

IMPORTANTE

1. A chave privada correspondente à chave pública didática não está incluída.
2. Gere seu próprio par RSA para as demais atividades.
3. Nunca entregue sua chave privada nem a senha do arquivo PEM.
4. Leia arquivos de entrada em modo binário.
5. Use RSA-OAEP apenas para encapsular a chave AES; use AES-GCM para os dados.
6. AAD obrigatório: b"L2-CCSC-2026".
7. Uma assinatura válida só vincula o conteúdo à chave correspondente. A
   confiança na identidade exige autenticação da chave pública.

VALIDAÇÃO

Compare os resumos SHA-256 dos arquivos originais e recuperados. A assinatura
fornecida deve ser válida para o comunicado original e inválida após qualquer
alteração no conteúdo.

