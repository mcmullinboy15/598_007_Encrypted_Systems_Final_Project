## Each database looks like this
```
[db] data
col1    col2            col3            col4            col5
11      12              13              14              15
21      22              23              24              25
31      32              33              34              35
41      42              43              44              45
51      52              53              54              55
```

## Set/Create Scheme
```
cnx, cursor = self.connect()

cursor.execute("DROP DATABASE IF EXISTS es;")
cursor.execute("CREATE DATABASE IF NOT EXISTS es;")
cursor.execute("USE es;")

cursor.execute("""
    CREATE TABLE main (
        col1 VARCHAR(50) NOT NULL,
        col2 VARCHAR(50) NOT NULL,
        col3 VARCHAR(50) NOT NULL,
        col4 VARCHAR(50) NOT NULL,
        col5 VARCHAR(50) NOT NULL);""")

cursor.execute("""
    INSERT INTO main (col1, col2, col3, col4, col5)
    VALUES
        (11, 12, 13, 14, 15),
        (21, 22, 23, 24, 25),
        (31, 32, 33, 34, 35),
        (41, 42, 43, 44, 45),
        (51, 52, 53, 54, 55)
""")
cnx.commit()


cursor.close()
cnx.close()
```

## To get data
    SELECT * FROM main;