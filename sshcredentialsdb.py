import sqlite3
import os

class Database:
    """
    This class handles the connection to the sqlite3 database
    """
    def __init__(self,db_name):
        """
        Opens a connection to the database
        """
        self.con = sqlite3.connect(db_name)
        cur = self.con.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS credentials(
                                id integer PRIMARY KEY AUTOINCREMENT,
                                username text NOT NULL,
                                password text NOT NULL,
                                ssh_machine text NOT NULL,
                                connection_timestamp integer
                            );""")
    def conn(self):
        """
        Returns a connection
        """
        return self.con
    
class CredentialsStore:
    """
    This class stores and retrieves the ssh credentials on the sqlite3 database
    """
    def __init__(self,db_name):
        """
        Initializes the connection
        """
        self.db = Database(db_name)

    def add_credentials(self , username , password , ssh_machine):
        """
        Adds new credentials to the database
        """
        sql = ''' INSERT INTO credentials(username,password,ssh_machine,connection_timestamp)
              VALUES(?,?,?,CURRENT_TIMESTAMP) '''
        conn = self.db.conn()
        cur = conn.cursor()
        cur.execute(sql, [username, password , ssh_machine])
        conn.commit()
        
    def get_all_credentials(self):
        """
        Retrieves all saved credentials from the database
        """
        conn = self.db.conn()
        cur = conn.cursor()
        cur.execute("SELECT username,password,ssh_machine,connection_timestamp FROM credentials")
        rows = cur.fetchall()
        return rows
    
    def get_credentials_by_username(self,username):
        """
        Retrieves all saved credentials from the database that have a certain username
        """
        conn = self.db.conn()
        cur = conn.cursor()
        cur.execute("SELECT username,password,ssh_machine,connection_timestamp FROM credentials WHERE username = ?",[username])
        rows = cur.fetchall()
        return rows
    
    def get_credentials_by_machine(self,sshmachine_ip):
        """
        Retrieves all saved credentials from the database that were used to connect to a certain ip address
        """
        conn = self.db.conn()
        cur = conn.cursor()
        cur.execute("SELECT username,password,ssh_machine,connection_timestamp FROM credentials WHERE ssh_machine = ?",[sshmachine_ip])
        rows = cur.fetchall()
        return rows
    
    def get_credentials_by_username_and_machine(self,username,sshmachine_ip):
        """
        Retrieves all saved credentials from the database that have a certain username and were used to connect to a certain ip address
        """
        conn = self.db.conn()
        cur = conn.cursor()
        cur.execute("SELECT username,password,ssh_machine,connection_timestamp FROM credentials WHERE username = ? AND ssh_machine = ?",[username,sshmachine_ip])
        rows = cur.fetchall()
        return rows
