import sqlite3
import os
import hashlib  

db_filename = 'potatoes.db'

if os.path.exists(db_filename):
    os.remove(db_filename)

conn = sqlite3.connect(db_filename)

conn.execute('''
    CREATE TABLE IF NOT EXISTS table1 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        field1 TEXT NOT NULL,
        field2 TEXT NOT NULL,
        field3 TEXT NOT NULL,
        field4 TEXT NOT NULL,
        field5 TEXT NOT NULL,
        field6 TEXT NOT NULL
    )
''')

# Create a table for storing user information
conn.execute('''
    CREATE TABLE IF NOT EXISTS table2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        field1 TEXT NOT NULL,
        field2 TEXT NOT NULL,
        field3 TEXT NOT NULL
    )
''')


conn.executemany('''
    INSERT INTO potatoes (field1, field2, field3, field4, field5, field6)
    VALUES (?, ?, ?, ?, ?, ?)
''', [
    ('a', 'b', 'c', 'd', 'e', 'f')
])

conn.executemany('''
    INSERT INTO table2 (field1, field2, field3)
    VALUES (?, ?, ?)
''', [
    ('a', 'b', 'c')
])

conn.commit()
conn.close()

