"""
Démo de concept : chiffrement authentifié avec Fernet + décorticage du token.

Le programme chiffre une phrase, puis OUVRE le token pour montrer, octet par
octet, les champs qu'il contient (version, horodatage, IV, texte chiffré, HMAC).
Enfin il "oublie" la phrase d'origine et la reconstruit à partir du seul token.

Fernet = AES-128-CBC (confidentialité) + HMAC-SHA256 (intégrité).
"""

import base64
from datetime import datetime

from cryptography.fernet import Fernet


def decortiquer(token: bytes) -> None:
    """Ouvre un token Fernet et affiche ses champs un par un.

    PIÈGE À CONNAÎTRE : le token est encodé en base64url. Il faut donc le
    DÉCODER d'abord pour retrouver les octets bruts, PUIS découper. Les tailles
    des champs sont fixes, sauf le texte chiffré (le "reste" au milieu) :
        version (1) | horodatage (8) | IV (16) | chiffré (n) | HMAC (32)
    """
    brut = base64.urlsafe_b64decode(token)

    version = brut[0]
    horodatage = brut[1:9]
    iv = brut[9:25]
    chiffre = brut[25:-32]
    hmac = brut[-32:]

    # L'horodatage est un entier big-endian = secondes depuis 1970.
    date = datetime.fromtimestamp(int.from_bytes(horodatage, "big"))

    # On montre d'abord le token en octets bruts, à plat : c'est CETTE suite
    # que le découpage ci-dessous vient trancher à des positions fixes.
    print("\n[+] Token décodé (octets bruts) :")
    print(" ", brut.hex(" "))

    print("\n[+] Découpage de ces mêmes octets :")
    print(f"  ─ Version    (1 o)  : {version:02x}")
    print(f"  ─ Horodatage (8 o)  : {horodatage.hex()}   → {date:%Y-%m-%d %H:%M:%S}")
    print(f"  ─ IV         (16 o) : {iv.hex(' ')}")
    print(f"  ─ Chiffré    ({len(chiffre)} o) : {chiffre.hex(' ')}")
    print(f"  ─ HMAC       (32 o) : {hmac.hex(' ')}")


def main():
    # 1. Génération de la clé (la même chiffre et déchiffre).
    cle = Fernet.generate_key()
    fernet = Fernet(cle)
    print("[i] Clé générée :", cle.decode())

    # 2. Saisie de la phrase.
    phrase = input("\nEntrez une phrase à chiffrer : ")

    # 3. Chiffrement.
    token = fernet.encrypt(phrase.encode())
    print("\n[+] Token complet :")
    print(token.decode())

    # 4. Décorticage : on montre ce qu'il y a VRAIMENT dans le token.
    decortiquer(token)

    # 5. On "oublie" la phrase d'origine.
    del phrase
    print("\n[i] Phrase d'origine oubliée (variable supprimée).")

    # 6. Déchiffrement à partir du seul token + la clé.
    phrase_retrouvee = fernet.decrypt(token).decode()
    print("\n[+] Version déchiffrée :")
    print(phrase_retrouvee)


if __name__ == "__main__":
    main()