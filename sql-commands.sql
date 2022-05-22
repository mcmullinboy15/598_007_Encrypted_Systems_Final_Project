ALTER TABLE main DISCARD TABLESPACE;
ALTER TABLE main IMPORT  TABLESPACE;

CREATE TABLESPACE main ADD DATAFILE 'main.ibd' ENCRYPTION = 'Y' ENGINE=InnoDB;

ALTER TABLE main ENCRYPTION='Y';

## Many of the SQL commands are here:
https://dev.mysql.com/doc/refman/5.7/en/innodb-table-import.html
+ internals has info