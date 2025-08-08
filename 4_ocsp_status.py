# 4_ocsp_status.py - OCSP good/revoked, soft-fail vs hard-fail
import json, os, time
from toy_pki import Cert, CA, TrustStore, check_ocsp, OCSPStatus, now_ts

OUT = "out_pki"

# Root & certs
with open(os.path.join(OUT, "root_ca.secret"), "rb") as f:
    root_secret = f.read()
root = CA("RootCA", secret=root_secret)

def load_cert(fname):
    with open(os.path.join(OUT, fname), "r") as f:
        d = json.load(f)
    return Cert(**{k: d[k] for k in d if k != "signature"}, signature=d["signature"])

bob_cert = load_cert("bob_cert.json")
alice_cert = load_cert("alice_cert.json")

# Trust
trust = TrustStore()
trust.add_root(root)

# Bob revogado (depois de rodar 3_crl_revocation.py), Alice good
ocsp_bob = root.ocsp_status(bob_cert.serial)
ocsp_alice = root.ocsp_status(alice_cert.serial)

print("OCSP Bob:", check_ocsp(bob_cert, ocsp_bob, trust, soft_fail=False))
print("OCSP Alice:", check_ocsp(alice_cert, ocsp_alice, trust, soft_fail=True))

# OCSP quebrado (assinatura inválida) → compara soft vs hard fail
bad = OCSPStatus(cert_serial=alice_cert.serial, status="good",
                 this_update=now_ts(), next_update=now_ts()+300, signature="lixo")
print("OCSP Alice (soft-fail):", check_ocsp(alice_cert, bad, trust, soft_fail=True))
print("OCSP Alice (hard-fail):", check_ocsp(alice_cert, bad, trust, soft_fail=False))
