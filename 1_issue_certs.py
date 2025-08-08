# 1_issue_certs.py - Emitir Root, sub-CA e usuários; salvar JSON
import json, os
from toy_pki import CA, TrustStore

OUT = "out_pki"
os.makedirs(OUT, exist_ok=True)

# Root
root = CA("RootCA")
# Sub-CA, emitida pela Root (neste modelo, vamos fazer a Root assinar o cert da Sub)
sub_cert, _ = root.issue_cert("SubCA", is_ca=True, validity_days=3650, key_usage=["sign"])
# Usuários (EE), assinados pela Sub-CA (correto para a cadeia EE->Sub->Root)
sub = CA("SubCA", parent=root, secret=None)  # a “entidade Sub” com o mesmo nome
sub.secret = root.secret  # *didático*: reaproveitamos segredo pra validação simples

bob_cert, bob_pub = sub.issue_cert("Bob (encryption)", is_ca=False, validity_days=365, key_usage=["enc"])
alice_cert, alice_pub = sub.issue_cert("Alice (signature)", is_ca=False, validity_days=365, key_usage=["sign"])

# Trust store conhece a raiz
trust = TrustStore()
trust.add_root(root)

# Salva tudo
with open(os.path.join(OUT, "root_ca.secret"), "wb") as f: f.write(root.secret)
for name, obj in {
    "sub_cert.json": sub_cert.to_json(),
    "bob_cert.json": bob_cert.to_json(),
    "alice_cert.json": alice_cert.to_json(),
}.items():
    with open(os.path.join(OUT, name), "w") as f: f.write(obj)

print(f"Emitidos certificados em ./{OUT}/")
