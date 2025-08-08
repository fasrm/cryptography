# -*- coding: utf-8 -*-
# Demo: Distribuição de chaves com Shamir (t-of-n) + KEK wrapping de Data Key (AES-GCM)

import secrets
import base64
from typing import List, Tuple

try:
    from Crypto.Cipher import AES
except ImportError:
    raise SystemExit("Instale pycryptodome: pip install pycryptodome")

# ---------- Matemática de Shamir (GF(p)) ----------
# Primo p > 2^256 (usamos o primo da secp256k1)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def mod_inv(a: int, p: int = P) -> int:
    # inverso multiplicativo modulo p
    return pow(a, p - 2, p)

def eval_poly(coeffs: List[int], x: int, p: int = P) -> int:
    # avalia polinômio em x (coef[0] = termo constante = segredo)
    y = 0
    for c in reversed(coeffs):
        y = (y * x + c) % p
    return y

def shamir_split(secret: bytes, n: int, t: int) -> List[Tuple[int, int]]:
    """
    Divide secret (bytes) em n partes com limiar t.
    Retorna lista de (x, y) inteiros.
    """
    if not (1 <= t <= n):
        raise ValueError("Exija 1 <= t <= n")
    s_int = int.from_bytes(secret, "big")
    if s_int >= P:
        raise ValueError("Segredo muito grande para o primo escolhido")
    # polinômio de grau t-1 com termo constante = segredo
    coeffs = [s_int] + [secrets.randbelow(P) for _ in range(t - 1)]
    shares = []
    used_x = set()
    for _ in range(n):
        # x únicos em [1, P-1]
        while True:
            x = secrets.randbelow(P - 1) + 1
            if x not in used_x:
                used_x.add(x)
                break
        y = eval_poly(coeffs, x)
        shares.append((x, y))
    return shares

def shamir_combine(shares: List[Tuple[int, int]]) -> bytes:
    """
    Reconstrói o segredo a partir de t shares (x, y) usando interpolação de Lagrange em x=0.
    """
    if len(shares) == 0:
        raise ValueError("Forneça pelo menos 1 share")
    x_vals, y_vals = zip(*shares)
    # Verifica unicidade dos x
    if len(set(x_vals)) != len(x_vals):
        raise ValueError("Shares com x duplicado")
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        # Lagrange basis L_j(0)
        num = 1
        den = 1
        for m, (xm, _) in enumerate(shares):
            if m == j:
                continue
            num = (num * (-xm % P)) % P   # (0 - xm)
            den = (den * (xj - xm) ) % P
        lj = (num * mod_inv(den % P)) % P
        secret = (secret + (yj * lj)) % P
    # converte para 32 bytes (tamanho da Data Key/KEK)
    return secret.to_bytes(32, "big")

# ---------- Utilidades de “transporte” ----------
def serialize_share(share: Tuple[int, int]) -> str:
    x, y = share
    return base64.urlsafe_b64encode(x.to_bytes(32, "big") + y.to_bytes(32, "big")).decode()

def deserialize_share(s: str) -> Tuple[int, int]:
    b = base64.urlsafe_b64decode(s.encode())
    if len(b) != 64:
        raise ValueError("Share inválido")
    return int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big")

# ---------- AES-GCM para “embrulhar” a Data Key com o KEK ----------
def wrap_with_kek(kek: bytes, data_key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Retorna (iv, ciphertext, tag) de AES-GCM sob KEK.
    """
    iv = secrets.token_bytes(12)
    cipher = AES.new(kek, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data_key)
    return iv, ct, tag

def unwrap_with_kek(kek: bytes, iv: bytes, ct: bytes, tag: bytes) -> bytes:
    cipher = AES.new(kek, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)

# ---------- Demo ponta a ponta ----------
def demo(n=5, t=3):
    print(f"\n=== DEMO: Shamir t-of-n (t={t}, n={n}) + KEK/DataKey ===")

    # 1) Gera KEK (Key-Encryption Key) e Data Key
    kek = secrets.token_bytes(32)       # 256-bit KEK
    data_key = secrets.token_bytes(32)  # 256-bit Data Key

    # 2) Envolve (wrap) a Data Key com o KEK (o que trafega/permanece guardado é o ciphertext)
    iv, ct, tag = wrap_with_kek(kek, data_key)
    print(f"KEK gerado (oculto); DataKey embrulhada (iv|ct|tag len={len(iv)}|{len(ct)}|{len(tag)})")

    # 3) Divide o KEK em shares (t-of-n) e “envia por canais” (simulação)
    shares = shamir_split(kek, n=n, t=t)
    b64_shares = [serialize_share(sh) for sh in shares]
    canais = ["telefone", "correio", "mensageiro", "email_sec", "pombo-correio"]
    print("\nShares distribuídos por canais diferentes:")
    for i, s in enumerate(b64_shares):
        canal = canais[i % len(canais)]
        print(f"  - Canal {canal:13s}: share[{i}] = {s[:44]}...")

    # 4) Receptor reúne QUALQUER subconjunto de t shares
    subset = [deserialize_share(s) for s in b64_shares[:t]]  # simula receber só t
    kek_rec = shamir_combine(subset)
    assert kek_rec == kek, "Reconstrução do KEK falhou"

    # 5) Receptor usa o KEK reconstruído para “desembrulhar” a Data Key
    data_key_rec = unwrap_with_kek(kek_rec, iv, ct, tag)
    assert data_key_rec == data_key, "Falha ao recuperar Data Key"

    # 6) Usa a Data Key para cifrar/decifrar uma mensagem (AES-GCM novamente)
    msg = b"Mensagem ultra-confidencial: contrato X-42."
    iv2 = secrets.token_bytes(12)
    aead = AES.new(data_key_rec, AES.MODE_GCM, nonce=iv2)
    ct2, tag2 = aead.encrypt_and_digest(msg)

    aead2 = AES.new(data_key_rec, AES.MODE_GCM, nonce=iv2)
    dec = aead2.decrypt_and_verify(ct2, tag2)
    assert dec == msg

    print("\n[OK] KEK reconstruído com t shares.")
    print("[OK] Data Key recuperada e usada com sucesso.")
    print(f"[OK] Mensagem decifrada: {dec.decode(errors='ignore')}")
    print("\nResumo para transporte/armazenamento seguro:")
    print(f"  - Guardar KEK? NÃO (somente shares t-of-n, separados por canais)")
    print(f"  - Guardar DataKey? NÃO (guardar apenas iv|ct|tag do wrap, e rotacionar DataKey)")
    print(f"  - Para recuperar: juntar >= {t} shares → KEK → unwrap(DataKey) → usar\n")

if __name__ == "__main__":
    demo(n=5, t=3)
