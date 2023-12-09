import hashlib
import re

def verification_de_motpasse():
    print("Votre mot de passe doit contenir 1 majuscule, 1 minuscule, un caractère spécial et doit contenir au moins 8 caractères")

    while True:
        mot_de_passe = input("Veuillez rentrer votre mot de passe : ")
    # Vérification des exigences du mot de passe
        if len(mot_de_passe) < 8:
            print("Erreur : Le mot de passe doit faire 8 caractères minimum")
            continue
        if not re.search("[A-Z]", mot_de_passe):
            print("Erreur : Votre mot de passe doit contenir au minimum 1 caractère en majusucle")
            continue
        if not re.search("[a-z]", mot_de_passe):
            print("Erreur : Votre mot de passe doit contenir au minimum 1 caractère minuscule")
            continue
        if not re.search("\d", mot_de_passe):
            print("Erruer : Votre mot de passe doit contenir au moins 1 chiffre")
            continue
        if not re.search(r"[!@#$%^&*]", mot_de_passe):
            print("Erreur : Votre mot de passe doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *)")
            continue

        print("Votre mot de passe est valide")
        return mot_de_passe

def cryptage_mdp(mot_de_passe):
    shamdp = hashlib.sha256(mot_de_passe.encode()).hexdigest()
    return shamdp

mot_de_passe_valide = verification_de_motpasse()
mot_de_passe_crypte = cryptage_mdp(mot_de_passe_valide)
print("Votre mot de passe crypté :", mot_de_passe_crypte)
                        
        
