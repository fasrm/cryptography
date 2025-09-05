"""
Chaum-Pedersen Zero-Knowledge Proof (demo didático em Z_p*).

Mostra uma rodada honesta (passa) e uma rodada trapaceando (falha).

Use p primo pequeno para visualizar. Em prática, use curvas elípticas / primos enormes.
"""

from random import SystemRandom

rand = SystemRandom()  # gerador aleatório melhor que random() para criptografia didática


def prime_factors(n: int) -> set[int]:
    """Fatora n em primos (simples, suficiente para p-1 pequeno)."""
    f, res = 2, set()
    while f * f <= n:
        if n % f == 0:
            res.add(f)
            while n % f == 0:
                n //= f
        f += 1 if f == 2 else 2  # pula pares depois do 2
    if n > 1:
        res.add(n)
    return res


def find_generator_mod_p(p: int) -> int:
    """
    Encontra um gerador de Z_p* assumindo p primo.
    g é gerador se g^((p-1)/q) != 1 (mod p) para todo primo q | (p-1).
    """
    assert p > 2, "p deve ser primo > 2"
    phi = p - 1
    factors = prime_factors(phi)
    for g in range(2, p - 1):
        if all(pow(g, phi // q, p) != 1 for q in factors):
            return g
    raise RuntimeError("nenhum gerador encontrado (p não é primo?)")


def chaum_pedersen_round(p: int = 23) -> dict:
    """
    Executa UMA rodada honesta do protocolo Chaum–Pedersen em Z_p*.
    Retorna a transcrição completa e o resultado das checagens.
    """
    order = p - 1
    g = find_generator_mod_p(p)

    # escolhe h = g^t
    t = rand.randrange(2, order)
    h = pow(g, t, p)

    # segredo do provador
    x = rand.randrange(2, order)
    gx = pow(g, x, p)
    hx = pow(h, x, p)

    # compromisso
    r = rand.randrange(1, order)
    a = pow(g, r, p)
    b = pow(h, r, p)

    # desafio
    c = rand.randrange(1, order)

    # resposta
    z = (r + c * x) % order

    # verificação
    ok1 = pow(g, z, p) == (a * pow(gx, c, p)) % p
    ok2 = pow(h, z, p) == (b * pow(hx, c, p)) % p

    return {
        "p": p,
        "order": order,
        "g": g,
        "h": h,
        "x (secret)": x,
        "gx": gx,
        "hx": hx,
        "r": r,
        "a": a,
        "b": b,
        "c": c,
        "z": z,
        "check1": ok1,
        "check2": ok2,
    }


def verify_transcript(p: int, g: int, h: int, gx: int, hx: int, a: int, b: int, c: int, z: int) -> tuple[bool, bool]:
    """Verifica as duas igualdades do protocolo."""
    left1 = pow(g, z, p)
    right1 = (a * pow(gx, c, p)) % p
    left2 = pow(h, z, p)
    right2 = (b * pow(hx, c, p)) % p
    return left1 == right1, left2 == right2


def cheat_round(p: int = 23) -> dict:
    """
    Gera uma transcrição e altera z para simular trapaceiro.
    Resultado deve falhar na verificação.
    """
    t = chaum_pedersen_round(p)
    order = p - 1
    t["z"] = (t["z"] + 1) % order  # z incorreto
    t["check1"], t["check2"] = verify_transcript(
        t["p"], t["g"], t["h"], t["gx"], t["hx"], t["a"], t["b"], t["c"], t["z"]
    )
    return t


def pretty_print(title: str, T: dict) -> None:
    print(f"\n=== {title} ===")
    for k in [
        "p", "g", "h", "x (secret)", "gx", "hx", "r", "a", "b", "c", "z", "check1", "check2",
    ]:
        print(f"{k:>12}: {T[k]}")



if __name__ == "__main__":
    # escolha um primo pequeno para brincar (ex.: 23, 29, 31, 53...)
    p = 29

    honest = chaum_pedersen_round(p)
    pretty_print("Rodada honesta (deve PASSAR)", honest)

    cheater = cheat_round(p)
    pretty_print("Rodada trapaceando (deve FALHAR)", cheater)


"""
Result:

if __name__ == "__main__":
    # escolha um primo pequeno para brincar (ex.: 23, 29, 31, 53...)
    p = 29

    honest = chaum_pedersen_round(p)
    pretty_print("Rodada honesta (deve PASSAR)", honest)

    cheater = cheat_round(p)
    pretty_print("Rodada trapaceando (deve FALHAR)", cheater)
"""
