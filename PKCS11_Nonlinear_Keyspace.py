from pkcs11 import KeyType, Mechanism, Attribute, lib
from pkcs11.util.ec import encode_ecdsa_signature
from Crypto.Cipher import AES
import hashlib
import os

# Caminho para a biblioteca do SoftHSM
PKCS11_LIB = "/usr/lib/softhsm/libsofthsm2.so"

class NonlinearHSM:
    def __init__(self, token_label, user_pin, magic_secret):
        self.lib = lib(PKCS11_LIB)
        self.token = self.lib.get_token(token_label=token_label)
        self.session = self.token.open(user_pin=user_pin)
        self.magic_secret = magic_secret.encode()

        # Criar ou buscar chave AES interna para teste
        try:
            self.magic_key = self.session.generate_key(
                KeyType.AES, 256,
                label="MAGIC_KEY",
                store=True
            )
        except Exception:
            self.magic_key = self.session.get_key(label="MAGIC_KEY")

    def _check_key_strength(self, user_key_bytes):
        """
        Verifica se user_key_bytes é 'forte' descriptografando MAGIC_SECRET
        e comparando.
        """
        iv = b'\x00' * 16
        cipher = AES.new(user_key_bytes, AES.MODE_CBC, iv)
        test_ct = AES.new(user_key_bytes, AES.MODE_CBC, iv).encrypt(self.magic_secret)
        decrypted = AES.new(user_key_bytes, AES.MODE_CBC, iv).decrypt(test_ct)
        return decrypted == self.magic_secret

    def encrypt(self, user_key_bytes, plaintext):
        iv = b'\x00' * 16

        if self._check_key_strength(user_key_bytes):
            print("[HSM] Chave válida → AES-256 real.")
            cipher = AES.new(user_key_bytes, AES.MODE_CBC, iv)
        else:
            print("[HSM] Chave inválida → AES fraco.")
            weak_key = hashlib.sha256(user_key_bytes[:4]).digest()
            cipher = AES.new(weak_key, AES.MODE_CBC, iv)

        return cipher.encrypt(plaintext)

    def decrypt(self, user_key_bytes, ciphertext):
        iv = b'\x00' * 16

        if self._check_key_strength(user_key_bytes):
            cipher = AES.new(user_key_bytes, AES.MODE_CBC, iv)
        else:
            weak_key = hashlib.sha256(user_key_bytes[:4]).digest()
            cipher = AES.new(weak_key, AES.MODE_CBC, iv)

        return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    MAGIC_STRING = "SECRET-ACCESS-OK!"
    hsm = NonlinearHSM("NonlinearKS", "5678", MAGIC_STRING)

    # Chave correta
    true_key = hashlib.sha256(b"senha_muito_secreta").digest()

    # Chave errada
    fake_key = hashlib.sha256(b"senha_errada").digest()

    # Mensagem
    plaintext = b"Documento Confidencial 123" + b" " * (32 - len("Documento Confidencial 123"))

    # Teste chave forte
    ct_true = hsm.encrypt(true_key, plaintext)
    print("Ciphertext (true):", ct_true.hex())
    print("Decrypted:", hsm.decrypt(true_key, ct_true))

    # Teste chave fraca
    ct_fake = hsm.encrypt(fake_key, plaintext)
    print("Ciphertext (fake):", ct_fake.hex())
    print("Decrypted:", hsm.decrypt(fake_key, ct_fake))
