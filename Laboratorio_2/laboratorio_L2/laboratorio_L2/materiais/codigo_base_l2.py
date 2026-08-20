"""Código-base do Laboratório L2 — Criptografia Assimétrica.

Complete somente os trechos marcados com TODO. Não inclua chaves privadas,
senhas ou dados reais no arquivo de entrega.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"L2-CCSC-2026"


def gerar_par_rsa():
    """Retorna (chave_privada, chave_publica) para RSA-3072/e=65537."""
    # TODO: implemente.
    raise NotImplementedError


def salvar_chaves(chave_privada, chave_publica, senha: bytes,
                  pasta: Path = Path("chaves")) -> None:
    """Salva a chave privada em PKCS#8 cifrado e a pública em SPKI/PEM."""
    # TODO: crie a pasta, serialize e grave as duas chaves.
    raise NotImplementedError


def carregar_chave_privada(caminho: Path, senha: bytes):
    """Carrega uma chave privada PEM protegida por senha."""
    # TODO: implemente.
    raise NotImplementedError


def carregar_chave_publica(caminho: Path):
    """Carrega uma chave pública PEM."""
    # TODO: implemente.
    raise NotImplementedError


def fingerprint_publica(chave_publica) -> str:
    """Retorna SHA-256 do DER/SPKI da chave pública em hexadecimal."""
    # TODO: serialize em DER/SPKI e calcule SHA-256.
    raise NotImplementedError


def _b64e(dados: bytes) -> str:
    return base64.b64encode(dados).decode("ascii")


def _b64d(texto: str) -> bytes:
    return base64.b64decode(texto.encode("ascii"), validate=True)


def cifrar_arquivo_hibrido(entrada: Path, saida: Path,
                           chave_publica) -> None:
    """Cifra um arquivo com AES-256-GCM e encapsula a chave com RSA-OAEP."""
    # TODO:
    # 1) leia bytes; 2) gere chave AES e nonce; 3) cifre com AAD;
    # 4) encapsule a chave AES com RSA-OAEP/SHA-256;
    # 5) grave o contêiner JSON com campos Base64.
    raise NotImplementedError


def decifrar_arquivo_hibrido(entrada: Path, saida: Path,
                             chave_privada) -> None:
    """Valida o contêiner, recupera a chave AES e decifra o arquivo."""
    # TODO: faça o processo inverso e rejeite algoritmo/AAD inesperados.
    raise NotImplementedError


def assinar(dados: bytes, chave_privada) -> bytes:
    """Assina dados usando RSA-PSS/MGF1-SHA256/SHA256."""
    # TODO: implemente.
    raise NotImplementedError


def verificar_assinatura(dados: bytes, assinatura: bytes,
                          chave_publica) -> bool:
    """Retorna True para assinatura válida e False para InvalidSignature."""
    # TODO: capture especificamente InvalidSignature.
    raise NotImplementedError


def sha256_arquivo(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def alterar_primeiro_byte_cifrado(entrada: Path, saida: Path) -> None:
    """Cria cópia adulterada do contêiner para o teste negativo."""
    pacote: dict[str, Any] = json.loads(entrada.read_text(encoding="utf-8"))
    cifrado = bytearray(_b64d(pacote["cifrado"]))
    if not cifrado:
        raise ValueError("Campo cifrado vazio")
    cifrado[0] ^= 0x01
    pacote["cifrado"] = _b64e(bytes(cifrado))
    saida.write_text(json.dumps(pacote, indent=2), encoding="utf-8")


def main() -> None:
    print("Laboratório L2: complete as funções TODO e organize seus testes.")
    print("AAD obrigatório:", AAD)


if __name__ == "__main__":
    main()

