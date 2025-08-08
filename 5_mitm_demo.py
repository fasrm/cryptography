# 5_mitm_demo.py - ataque de substituição (MITM)
import json, os
from toy_pki import Cert, CA, TrustStore, verify_chain

OUT = "out_pki"

# Root e Sub legítimos
with open(os.path.join(OUT, "root_ca.secret"), "rb") as f:
    root_secret = f.read()
root = CA("RootCA", secret=root_secret)

def load_cert(fname):
    with open(os.path.join(OUT, fname), "r") as f:
        d = json.load(f)
    return Cert(**{k: d[k] for k in d if k != "signature"}, signature=d["signature"])

sub_cert = load_cert("sub_cert.json")

# Mallory cria CA fake e um "cert do Bob"
fake_ca = CA("FakeCA")
mallory_cert, _ = fake_ca.issue_cert("Bob (fake)", is_ca=False, validity_days=365, key_usage=["enc"])

# Cadeia apresentada ao cliente inocente
chain_mitm = [mallory_cert, sub_cert]

# Trust só confia na Root legítima
trust = TrustStore()
trust.add_root(root)

print("MITM result:", verify_chain(chain_mitm, trust))
