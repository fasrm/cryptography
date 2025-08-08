# 2_verify_chain.py - validar cadeia (EE → Sub → Root)
import json, os
from toy_pki import Cert, CA, TrustStore, verify_chain

OUT = "out_pki"

# Reconstrói Root
with open(os.path.join(OUT, "root_ca.secret"), "rb") as f:
    root_secret = f.read()
root = CA("RootCA", secret=root_secret)

# Carrega certs
def load_cert(fname):
    with open(os.path.join(OUT, fname), "r") as f:
        d = json.load(f)
    return Cert(**{k: d[k] for k in d if k != "signature"}, signature=d["signature"])

sub_cert = load_cert("sub_cert.json")
bob_cert = load_cert("bob_cert.json")
alice_cert = load_cert("alice_cert.json")

# Trust store
trust = TrustStore()
trust.add_root(root)

# Cadeias: [EE, Sub]
chain_bob = [bob_cert, sub_cert]
chain_alice = [alice_cert, sub_cert]

print("Bob:", verify_chain(chain_bob, trust))
print("Alice:", verify_chain(chain_alice, trust))
