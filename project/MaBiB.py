# imports
import hashlib
import os
import re

import getpass4
from crypto.Cipher import AES, PKCS1_OAEP
from crypto.PublicKey import RSA
from crypto.Signature import pkcs1_15
from crypto.Hash import SHA256
from crypto.Random import get_random_bytes


# consts
regex = re.compile(
    r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
file_path = "Authentification.txt"
Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ListeMD5 = []
ListeSHA256 = []
ListeBlake2b = []


# functions

def menu_principal():
    print("| Application Multi Taches |")
    print("--------| Menu Principal |--------")
    print("A- Enregistrement")
    print("B- Authentification")
    print("C- Quitter")
    return input("entrer une option : ")


def menu_a():
    print("--------|       Menu A : Enregistrement      |--------")
    print("A1- Sauvegarder Données utilisateur")
    print("A2- Lire Données utilisateur ")
    print("A3- Revenir au menu principal")
    return input("entrer une option : ")


def enregistrement():
    while True:
        choixA = menu_a()
        if choixA == 'A1':
            enregistrement_donners_user()
        elif choixA == 'A2':
            afficher_donners_sauvegarder()
        elif choixA == 'A3':
            break
        else:
            print("Option non valide.")


def afficher_donners_sauvegarder():
    try:
        with open(file_path, "r") as file:
            data = file.read()
            print(data)
    except FileNotFoundError:
        print("Aucune donnée n'a été enregistrée.")


def menu_b1():
    print("--------|       Menu B1 :  Hachage      |--------")
    print("B1-a  Hacher un message par MD5")
    print("B1-b  Hacher un message par SHA256")
    print("B1-c  Hacher un message par Blake2b")
    print("B1-d  Cracker un message Haché")
    print("B1-e Revenir au menu MenuB")
    return input("entrer une option : ")


def hash_md5():
    ListeM = ["Password", "azerty", "shadow", "hunter"]
    ListeMH = ["3bf1114a986ba87ed28fc1b5884fc2f8",
               "0bb09d80600eec3eb9d7793a6f859bedde2a2d83899b70bd78e961ed674b32f4",
               "84cbb818cfade90c0630a1ee3145fdda66c1b1fb4862cc854c312c98c388dd84cb1f03d2ef97126071e9529943bf3da4abe0dacd2a5a85028381a65afe1e3623"]
    for word in ListeM:
        hashed_word = hashlib.md5(word.encode('utf-8')).hexdigest()
        print(f"{word} => {hashed_word}")
        ListeMD5.append(hashed_word)


def hash_SHA256():
    ListeM = ["Password", "azerty", "shadow", "hunter"]
    ListeMH = ["3bf1114a986ba87ed28fc1b5884fc2f8",
               "0bb09d80600eec3eb9d7793a6f859bedde2a2d83899b70bd78e961ed674b32f4",
               "84cbb818cfade90c0630a1ee3145fdda66c1b1fb4862cc854c312c98c388dd84cb1f03d2ef97126071e9529943bf3da4abe0dacd2a5a85028381a65afe1e3623"]
    for word in ListeM:
        hashed_word = hashlib.sha256(word.encode('utf-8')).hexdigest()
        print(f"{word} => {hashed_word}")
        ListeSHA256.append(hashed_word)


def hash_Blake2b():
    ListeM = ["Password", "azerty", "shadow", "hunter"]
    ListeMH = ["3bf1114a986ba87ed28fc1b5884fc2f8",
               "0bb09d80600eec3eb9d7793a6f859bedde2a2d83899b70bd78e961ed674b32f4",
               "84cbb818cfade90c0630a1ee3145fdda66c1b1fb4862cc854c312c98c388dd84cb1f03d2ef97126071e9529943bf3da4abe0dacd2a5a85028381a65afe1e3623"]
    for word in ListeM:
        hashed_word = hashlib.blake2b(word.encode('utf-8')).hexdigest()
        print(f"{word} => {hashed_word}")
        ListeBlake2b.append(hashed_word)


def trouver_indice_dans_liste_hachee():
    ListeMH = ["3bf1114a986ba87ed28fc1b5884fc2f8", "0bb09d80600eec3eb9d7793a6f859bedde2a2d83899b70bd78e961ed674b32f4",
               "84cbb818cfade90c0630a1ee3145fdda66c1b1fb4862cc854c312c98c388dd84cb1f03d2ef97126071e9529943bf3da4abe0dacd2a5a85028381a65afe1e3623"]
    ListeM = ["Password", "azerty", "shadow", "hunter"]

    def find_matching_word(hash_value, word_list, algorithm):
        for i, word in enumerate(word_list):
            if algorithm(word.encode()).hexdigest() == hash_value:
                return i
        return None

    for hash_value in ListeMH:
        for algorithm in [hashlib.md5, hashlib.sha256, hashlib.blake2b]:
            matching_word_index = find_matching_word(hash_value, ListeM, algorithm)
            if matching_word_index is not None:
                print(
                    f"Le mot correspondant au hachage {hash_value} (algorithme {algorithm.__name__}) est : {ListeM[matching_word_index]}")


def hachage():
    while True:
        choix = menu_b1()
        if (choix == "B1-A"):
            hash_md5()
        elif (choix == "B1-B"):
            hash_SHA256()
        elif (choix == "B1-C"):
            hash_Blake2b()
        elif (choix == "B1-D"):
            trouver_indice_dans_liste_hachee()
        elif (choix == "B1-E"):
            break
        else:
            print("Option non valide.")


def verifier_fichier_authentification():
    return os.path.exists(file_path)


def charger_donnees_authentification():
    fich = open(file_path, 'r', encoding='utf-8')
    data = fich.read()
    data = data.split('\n\n')
    user_list = {}
    for user_data in data:
        lines = user_data.splitlines()
        for lData in lines:
            combo = lData.split(" : ")
            if ("login&pwd" == combo[0]):
                su = combo[1].split("&")
                user_list[su[0]] = su[1]
    return user_list


def authentifier_utilisateur():
    if not verifier_fichier_authentification():
        print("Le fichier Authentification.txt n'existe pas. Veuillez vous enregistrer d'abord.")
        return
    print("erreur1")
    auth_dic = charger_donnees_authentification()
    print("erreur2")
    while True:
        print("erreur3")
        login = getpass4.getpass(prompt='Login : ')
        print("ereeur des ereuur")
        pwd = getpass4.getpass(prompt='pwd : ')
        print("erreur4")
        if login in auth_dic and auth_dic[login] == pwd:
            print("erreur5")
            print("Authentification réussie !")
            break
        else:
            print("erreur6")
            print("Authentification échouée. Veuillez réessayer ou vous enregistrer.")


def enregistrement_donners_user():
    user_id = input("Entrer le N° d'inscription : ")
    login = input("Entrer votre login : ")
    pwd = getpass4.getpass(prompt='Entrer votre pwd : ')
    while True:
        email = input('Entrer votre email :')
        if (re.fullmatch(regex, email)):
            break
        else:
            print("thabet email")

    classe = input("Introduire votre classe (CII-2-SIIR-A/B/C/D) : ").upper()

    while classe not in ['A', 'B', 'C', 'D']:
        classe = input(
            "Introduire votre classe (CII-2-SIIR-A/B/C/D) : ").upper()

    database = open(file_path, "a")  # append mode
    database.write(
        f"\nId_user : {user_id}\nlogin&pwd : {login}&{pwd}\nClasse : {classe}\nEmail : {email}\n")
    database.close()


def chiffrement():
    print("--------|    Menu B2 : Chiffrement    |--------")
    print("B2-a Cesar")
    print("B2-b Affine")
    print("B2-c RSA")
    print("B2-d Revenir au menu MenuB")

    choice = input("Enter your choice: ")
    if choice == "B2-a":
        menu_b2a()
    elif choice == "B2-b":
        menu_b2b()
    elif choice == "B2-c":
        menu_b2c()
    elif choice == "B2-d":
        chiffrement()
    else:
        print("Invalid choice. Please try again.")
        chiffrement()


def menu_b2a():
    print("--------|    Menu B2a : Chiffrement de Cesar    |--------")
    print("B2-a1 Chiffrement message")
    print("B2-a2 Déchiffrement message")
    print("B2-a3 Revenir au menu MenuB2")

    choice = input("Enter your choice: ")
    if choice == "B2-a1":
        caesar_encrypt()
    elif choice == "B2-a2":
        caesar_decrypt()
    elif choice == "B2-a3":
        chiffrement()
    else:
        print("Invalid choice. Please try again.")
        menu_b2a()


def menu_b2b():
    print("--------|    Menu B2b : Chiffrement Affine    |--------")
    print("B2-b1 Chiffrement message")
    print("B2-b2 Déchiffrement message")
    print("B2-b3 Revenir au menu MenuB2")

    choice = input("Enter your choice: ").upper()
    if choice == "B2-b1":
        affine_encrypt()
    elif choice == "B2-b2":
        affine_decrypt()
    elif choice == "B2-b3":
        chiffrement()
    else:
        print("Invalid choice. Please try again.")
        menu_b2b()


def rsa_verify(signature, message):
    hash = int.from_bytes(hashlib.sha512(message).digest(), byteorder='big')
    hashFromSignature = pow(signature, keyPair.e, keyPair.n)
    print("Signature valid:", hash == hashFromSignature)


def menu_b2c():
    print("--------|    Menu B2c : Chiffrement RSA    |--------")
    print("B2-c1 Chiffrement message")
    print("B2-c2 Déchiffrement message")
    print("B2-c3 Signature")
    print("B2-c4 Vérification Signature")
    print("B2-c5 Revenir au menu MenuB2")

    choice = input("Enter your choice: ")

    if choice == "B2-c1":
        rsa_encrypt()
    elif choice == "B2-c2":
        rsa_decrypt()
    elif choice == "B2-c3":
        message = input("Enter the message to sign with RSA: ")
        signature = rsa_sign(bytes(message, 'utf-8'))
        print("Signature:", hex(signature))
    elif choice == "B2-c4":
        message = input("Enter the message to sign with RSA: ")
        signature = rsa_sign(bytes(message, 'utf-8'))
        message = bytes(message, 'utf-8')
        rsa_verify(signature, message)
    elif choice == "B2-c5":
        chiffrement()
    else:
        print("Invalid choice. Please try again.")
        menu_b2c()


def caesar_encrypt():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = int(input("Enter the key for Caesar encryption (0-25): "))
    message = input("Enter the message to encrypt: ").upper()
    encrypted_message = ""

    for char in message:
        if char in alphabet:
            encrypted_char = alphabet[(alphabet.index(char) + key) % 26]
            encrypted_message += encrypted_char
        else:
            encrypted_message += char

    print("Encrypted message:", encrypted_message)


def caesar_decrypt():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = int(input("Enter the key for Caesar decryption (0-25): "))
    message = input("Enter the message to decrypt: ").upper()
    decrypted_message = ""

    for char in message:
        if char in alphabet:
            decrypted_char = alphabet[(alphabet.index(char) - key) % 26]
            decrypted_message += decrypted_char
        else:
            decrypted_message += char

    print("Decrypted message:", decrypted_message)


def affine_encrypt():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key_a = int(input("Enter the key 'a' for Affine encryption: "))
    key_b = int(input("Enter the key 'b' for Affine encryption: "))
    message = input("Enter the message to encrypt: ").upper()
    encrypted_message = ""

    for char in message:
        if char in alphabet:
            char_index = alphabet.index(char)
            encrypted_index = (key_a * char_index + key_b) % 26
            encrypted_char = alphabet[encrypted_index]
            encrypted_message += encrypted_char
        else:
            encrypted_message += char

    print("Encrypted message:", encrypted_message)


def affine_decrypt():
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key_a = int(input("Enter the key 'a' for Affine decryption: "))
    key_b = int(input("Enter the key 'b' for Affine decryption: "))
    message = input("Enter the message to decrypt: ").upper()
    decrypted_message = ""

    a_inverse = pow(key_a, -1, 26)

    for char in message:
        if char in alphabet:
            char_index = alphabet.index(char)
            decrypted_index = (a_inverse * (char_index - key_b)) % 26
            decrypted_char = alphabet[decrypted_index]
            decrypted_message += decrypted_char
        else:
            decrypted_message += char

    print("Decrypted message:", decrypted_message)


keyPair = RSA.generate(2048)
rsa_public_key = keyPair.publickey()
rsa_private_key = keyPair


def rsa_encrypt():
    message = input("Enter the message to encrypt with RSA: ")
    cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_message = cipher.encrypt(message.encode())
    print("Encrypted message:", encrypted_message.hex())


def rsa_decrypt():
    encrypted_message = input("Enter the encrypted message (in hexadecimal): ")
    encrypted_message = bytes.fromhex(encrypted_message)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    print("Decrypted message:", decrypted_message.decode())


def rsa_sign(message):
    # RSA sign the message
    print(message)
    hash = int.from_bytes(hashlib.sha512(message).digest(), byteorder='big')
    signature = pow(hash, keyPair.d, keyPair.n)
    print("Signature:", hex(signature))
    return signature

