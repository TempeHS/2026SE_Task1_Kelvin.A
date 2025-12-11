import sqlite3 as sql
import bcrypt

DB = "databaseFiles/database.db"


def getUsers():
    con = sql.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT * FROM id7_tusers")
    con.commit()
    con.close()


def NewUser(email, password):
    if not email or not password:
        return (False, "Email and password required")

    con = sql.connect(DB)
    cur = con.cursor()
    try:
        # Hash the password before storing
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cur.execute(
            "INSERT INTO id7_tusers (username, password) VALUES (?,?)",
            (email, hashed),
        )
        con.commit()
        con.close()
        return (True, "User created")
    except sql.IntegrityError:
        con.close()
        return (False, "User already exists")
    except Exception as e:
        try:
            con.close()
        except Exception:
            pass
        return (False, str(e))


def authenticate(email, password):
    if not email or not password:
        return False

    try:
        con = sql.connect(DB)
        cur = con.cursor()
        cur.execute("SELECT password FROM id7_tusers WHERE username =?", (email,))
        row = cur.fetchone()
        con.close()

        if not row:
            return False

        stored = row[0]

        if isinstance(stored, (bytes, bytearray, memoryview)):
            stored_bytes = bytes(stored)
            return bcrypt.checkpw(password.encode("utf-8"), stored_bytes)
        else:
            return password == stored
    except Exception:
        return False
