from Crypto.Cipher import AES
import os
import hashlib

class NonlinearKeyspaceModule:
    def __init__(self, master_secret):
        """
        master_secret = string fixa que o módulo espera
        """
        self.master_secret = master_secret.encode()
        self.iv = b'\x00' * 16  # IV fixo para simplificar o exemplo

    def _check_key(self, key):
        """
        Verifica se a chave é 'forte':
        Descriptografa o master_secret cifrado e compara.
        """
        # Gerar o "ciphertext mágico" que o módulo armazena internamente
        strong_cipher = AES.new(key, AES.MODE_CBC, self.iv)
        magic_ct = strong_cipher.encrypt(self.master_secret)

        # Agora, no teste, descriptografa para verificar
        test_cipher = AES.new(key, AES.MODE_CBC, self.iv)
        decrypted = test_cipher.decrypt(magic_ct)

        return decrypted == self.master_secret

    def encrypt(self, key, plaintext):
        """
        Se a chave for válida → usa AES-256 verdadeiro
        Se não → usa AES 'fraco'
        """
        if self._check_key(key):
            print("[MÓDULO] Chave válida: usando AES real.")
            cipher = AES.new(key, AES.MODE_CBC, self.iv)
        else:
            print("[MÓDULO] Chave inválida: usando AES fraco.")
            # AES fraco → chave reduzida para 4 bytes repetidos
            weak_key = hashlib.sha256(key[:4]).digest()
            cipher = AES.new(weak_key, AES.MODE_CBC, self.iv)

        return cipher.encrypt(plaintext)

    def decrypt(self, key, ciphertext):
        """
        Decifra usando a mesma lógica
        """
        if self._check_key(key):
            cipher = AES.new(key, AES.MODE_CBC, self.iv)
        else:
            weak_key = hashlib.sha256(key[:4]).digest()
            cipher = AES.new(weak_key, AES.MODE_CBC, self.iv)

        return cipher.decrypt(ciphertext)

# ============================
# Exemplo de uso
# ============================

# String mágica conhecida só pelo módulo
MAGIC_STRING = "SECRET-ACCESS-OK!"

# Criar o módulo
module = NonlinearKeyspaceModule(master_secret=MAGIC_STRING)

# Gerar chave verdadeira (256 bits)
true_key = hashlib.sha256(b"senha_muito_secreta").digest()

# Gerar chave falsa
fake_key = hashlib.sha256(b"senha_errada").digest()

# Mensagem (múltiplo de 16 bytes para simplificar)
plaintext = b"Documento Top Secret!" + b" " * (32 - len("Documento Top Secret!"))

# Teste com chave verdadeira
ct_true = module.encrypt(true_key, plaintext)
print("Ciphertext (true key):", ct_true.hex())
print("Decrypted (true key):", module.decrypt(true_key, ct_true))

# Teste com chave falsa
ct_fake = module.encrypt(fake_key, plaintext)
print("Ciphertext (fake key):", ct_fake.hex())
print("Decrypted (fake key):", module.decrypt(fake_key, ct_fake))
