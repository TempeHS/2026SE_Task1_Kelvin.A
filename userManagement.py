import sqlite3 as sql
import bcrypt

DB = "databaseFiles/database.db"


def getUsers():
    con = sql.connect(DB)
    cur = con.cursor()
    cur.execute("SELECT * FROM id7-tusers")
    con.commit()
    con.close()


def NewUser(email, password):

    if not email or not password:
        return (False, "Email n pass needed")

    con = sql.connect(DB)
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO id7_tusers (username, password) VALUES (?,?)",
            (email, password),
        )
        con.commit()
        con.close()
        return (True, "Table Created")
    except sql.IntegrityError:
        con.close()
        return (False, "")
    except Exception as e:
        con.close()
        return False
