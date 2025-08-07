import mongoengine

mongoengine.connect(
    db='mixout-core',
    host='mongo',
    port=27017,
    username=None,
    password=None
)

# Test rapido: conta i database disponibili
from mongoengine.connection import get_db
try:
    db = get_db()
    print("Connessione a MongoDB riuscita! Database:", db.name)
except Exception as e:
    print("Errore di connessione a MongoDB:", e)