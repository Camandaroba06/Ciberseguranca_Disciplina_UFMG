import secrets
import os
import pathlib
import base64

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