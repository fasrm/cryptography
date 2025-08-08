# toy_pki.py
# PKI didática: usa HMAC em vez de X.509 real, para ser 100% puro-Python.

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import hashlib, hmac, json, secrets, time, datetime
import base64

def now_ts() -> int:
    return int(time.time())

def b64(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).decode().rstrip("=")

def db64(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def format_ts(ts: int) -> str:
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")

@dataclass
class Cert:
    serial: str
    subject: str
    issuer: str
    not_before: int
    not_after: int
    public_key: str          # base64
    key_usage: List[str]     # ["enc"], ["sign"], ["auth"]...
    is_ca: bool = False
    signature: str = ""      # b64(HMAC(issuer_secret, canonical))

    def to_canonical(self) -> bytes:
        payload = {
            "serial": self.serial,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "public_key": self.public_key,
            "key_usage": self.key_usage,
            "is_ca": self.is_ca,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def to_json(self) -> str:
        return json.dumps({
            **json.loads(self.to_canonical().decode()),
            "signature": self.signature
        }, indent=2)

@dataclass
class CRLEntry:
    serial: str
    revoked_at: int
    reason: str

@dataclass
class CRL:
    issuer: str
    issued_at: int
    entries: List[CRLEntry] = field(default_factory=list)
    signature: str = ""

    def to_canonical(self) -> bytes:
        payload = {
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "entries": [e.__dict__ for e in self.entries]
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def to_json(self) -> str:
        return json.dumps({
            **json.loads(self.to_canonical().decode()),
            "signature": self.signature
        }, indent=2)

@dataclass
class OCSPStatus:
    cert_serial: str
    status: str        # "good", "revoked", "unknown"
    this_update: int
    next_update: int
    signature: str = ""

    def to_canonical(self) -> bytes:
        payload = {
            "cert_serial": self.cert_serial,
            "status": self.status,
            "this_update": self.this_update,
            "next_update": self.next_update
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def to_json(self) -> str:
        return json.dumps({
            **json.loads(self.to_canonical().decode()),
            "signature": self.signature
        }, indent=2)

class CA:
    def __init__(self, name: str, secret: Optional[bytes] = None, parent: Optional["CA"] = None):
        self.name = name
        self.secret = secret or secrets.token_bytes(32)  # HMAC key
        self.parent = parent
        self.issued: Dict[str, Cert] = {}
        self.revoked: Dict[str, CRLEntry] = {}

    def sign_cert(self, cert: Cert) -> Cert:
        cert.signature = b64(hmac_sha256(self.secret, cert.to_canonical()))
        self.issued[cert.serial] = cert
        return cert

    def issue_cert(self, subject: str, is_ca: bool, validity_days: int, key_usage: List[str]) -> Tuple[Cert, bytes]:
        pubkey = secrets.token_bytes(32)
        serial = b64(secrets.token_bytes(16))
        now = now_ts()
        cert = Cert(
            serial=serial,
            subject=subject,
            issuer=self.name,
            not_before=now - 60,
            not_after=now + validity_days * 86400,
            public_key=b64(pubkey),
            key_usage=key_usage,
            is_ca=is_ca,
        )
        return self.sign_cert(cert), pubkey

    def revoke(self, serial: str, reason: str = "keyCompromise") -> None:
        self.revoked[serial] = CRLEntry(serial=serial, revoked_at=now_ts(), reason=reason)

    def publish_crl(self) -> CRL:
        crl = CRL(self.name, now_ts(), list(self.revoked.values()))
        crl.signature = b64(hmac_sha256(self.secret, crl.to_canonical()))
        return crl

    def ocsp_status(self, serial: str, validity_sec: int = 300) -> OCSPStatus:
        now = now_ts()
        if serial in self.revoked:
            status = "revoked"
        elif serial in self.issued:
            status = "good"
        else:
            status = "unknown"
        ocsp = OCSPStatus(serial, status, now, now + validity_sec)
        ocsp.signature = b64(hmac_sha256(self.secret, ocsp.to_canonical()))
        return ocsp

class TrustStore:
    def __init__(self):
        self.roots: Dict[str, bytes] = {}  # CA name -> HMAC secret

    def add_root(self, ca: CA) -> None:
        self.roots[ca.name] = ca.secret

    def verify_sig(self, signer: str, data: bytes, sig_b64: str) -> bool:
        if signer not in self.roots:
            return False
        mac = hmac_sha256(self.roots[signer], data)
        return hmac.compare_digest(mac, db64(sig_b64))

def verify_chain(chain: List[Cert], trust: TrustStore) -> Tuple[bool, str]:
    if not chain:
        return False, "cadeia vazia"
    # validade temporal
    t = now_ts()
    for c in chain:
        if not (c.not_before <= t <= c.not_after):
            return False, f"{c.subject}: fora do período de validade"
    # checa que cada cert é assinado pelo 'issuer' que precisamos confiar (toy: confia direto na raiz)
    for cert in chain:
        if not trust.verify_sig(cert.issuer, cert.to_canonical(), cert.signature):
            return False, f"assinatura inválida para {cert.subject} (issuer {cert.issuer})"
    # checa encadeamento simples (EE -> issuer == nome do próximo.subject)
    for i in range(len(chain) - 1):
        if chain[i].issuer != chain[i+1].subject:
            return False, f"inconsistência na cadeia: {chain[i].subject} diz issuer {chain[i].issuer}, próximo é {chain[i+1].subject}"
    return True, "cadeia OK"

def check_crl(cert: Cert, crls: List[CRL], trust: TrustStore) -> Tuple[bool, str]:
    for crl in crls:
        if not trust.verify_sig(crl.issuer, crl.to_canonical(), crl.signature):
            return False, f"CRL inválida de {crl.issuer}"
        for e in crl.entries:
            if e.serial == cert.serial:
                return False, f"revogado ({e.reason} em {format_ts(e.revoked_at)})"
    return True, "não revogado nas CRLs"

def check_ocsp(cert: Cert, ocsp: OCSPStatus, trust: TrustStore, soft_fail: bool = True) -> Tuple[bool, str]:
    if not trust.verify_sig(cert.issuer, ocsp.to_canonical(), ocsp.signature):
        return (soft_fail, "OCSP inválido (assinatura); soft-fail aceita" if soft_fail else "OCSP inválido; hard-fail rejeita")
    t = now_ts()
    if not (ocsp.this_update <= t <= ocsp.next_update):
        return (soft_fail, "OCSP vencido; soft-fail aceita" if soft_fail else "OCSP vencido; hard-fail rejeita")
    if ocsp.status == "good":
        return True, "OCSP good"
    if ocsp.status == "revoked":
        return False, "OCSP revoked"
    return (soft_fail, "OCSP unknown; soft-fail aceita" if soft_fail else "OCSP unknown; hard-fail rejeita")
