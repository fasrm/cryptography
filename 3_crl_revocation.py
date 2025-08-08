# 3_crl_revocation.py - revogar e checar CRL
import json, os
from toy_pki import Cert, CA, TrustStore, CRL, check_crl

OUT = "out_pki"

# Root
with open(os.path.join(OUT, "root_ca.secret"), "rb") as f:
    root_secret = f.read()
root = CA("RootCA", secret=root_secret)

# Carrega certs
def load_cert(fname):
    with open(os.path.join(OUT, fname), "r") as f:
        d = json.load(f)
    return Cert(**{k: d[k] for k in d if k != "signature"}, signature=d["signature"])

bob_cert = load_cert("bob_cert.json")
alice_cert = load_cert("alice_cert.json")

# Revoga Bob
root.revoke(bob_cert.serial, reason="keyCompromise")
crl = root.publish_crl()

# Trust
trust = TrustStore()
trust.add_root(root)

# Checa CRL
ok_bob, msg_bob = check_crl(bob_cert, [crl], trust)
ok_alice, msg_alice = check_crl(alice_cert, [crl], trust)
print("Bob CRL:", ok_bob, "-", msg_bob)
print("Alice CRL:", ok_alice, "-", msg_alice)

# Salvar CRL
with open(os.path.join(OUT, "root_crl.json"), "w") as f:
    f.write(crl.to_json())
print(f"CRL salva em ./{OUT}/root_crl.json")
