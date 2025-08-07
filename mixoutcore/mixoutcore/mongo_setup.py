# mongo_setup.py
import mongoengine

def connect():
    mongoengine.connect(
        db='nome_db',           # Sostituisci con il nome del tuo database
        host='localhost',       # O l'URL di MongoDB Atlas
        port=27017,             # Porta di default
        username=None,          # Se hai autenticazione, metti username
        password=None           # Se hai autenticazione, metti password
    )