

from MaBiB import menu_principal, enregistrement, authentifier_utilisateur, hachage, chiffrement



while True:
    choixP = menu_principal()
    if choixP.isupper():
        if choixP == 'A':
            enregistrement()
        elif choixP == 'B':
            authentifier_utilisateur()
            while True:
                choixB = input("Menu Authentification - Choisissez B1 ou B2 (ou Q pour quitter) : ").upper()
                if choixB == 'B1':
                    hachage()
                elif choixB == 'B2':
                    chiffrement()
                elif choixB =='Q':
                    break
        elif choixP == 'C':
            print("Quitter l'application.")
            break
        else:
            print("Option non valide.")
    else:
        print("l'input doix etre MAJUSCULE")
