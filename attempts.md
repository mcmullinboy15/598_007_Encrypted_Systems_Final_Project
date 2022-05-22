## File Based
+ Fernet breaks and won't load for any single bit flip
+ AES does however allows for some changes

## MySQL Based
+ Just won't turn back on when the bits are flipped
    + this is due to the process, of stopping the SQL
    Server and then flipping bits on es/main.ibd


Errors i's: {}
Worked i's: [35, 36, 37]
+ But got error:
+ mysql.connector.errors.DatabaseError: 1812 (HY000): Tablespace is missing for table `es`.`main`.

# TO TRY
+ MENTION IT: change it to discard and import to see if I can get more working
+ look at 35, 36, 37 and see what happens.
+ finish the 114000
+ encrypt and try again.



