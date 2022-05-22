import os
from typing import List, Dict
import argcomplete
import argparse

import db

import ctypes, sys
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
if not is_admin():
    # Code of your program here
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)


# Config
def get_config(getter:str=None, encryptions:bool=False):
	"""
	getter:
		None -> Dict[str, Database]
		keys -> List[str]  
			<database_key> -> <database_class>
	encryptions:
		<getter is required>
		True  -> DATABASES[getter].encryptions
		False -> DATABASES[getter]
	"""

	config: Dict[str, db.Database] = db.get_dbs()

	if getter == "keys":
		return list(config.keys())

	elif getter in config:

		if encryptions:
			return config[getter].encryptions
		else:
			return config[getter]

	return config


def get_database(database:str=None):
	return get_config(database if database is not None else "keys")

def get_encryption_types(database):
	return get_config(database, encryptions=True)


# ArgumentParser
def get_argparser(argv:List=None):
	argparser = argparse.ArgumentParser()
	subparsers = argparser.add_subparsers(dest="type")
	subparsers.required = True

	exe_parser = subparsers.add_parser("run", help="Run all commands and see affect of flipping bits")

	status_parser = subparsers.add_parser("status", help="Display the status of the stated Database")
	data_parser = subparsers.add_parser("data", help="Print the first few rows and columns of the data")
	reset_data_parser = subparsers.add_parser("reset", help="Reset the Data Saved in the specified Database")

	encrypt_parser = subparsers.add_parser("encrypt", help="Add Encryption to the Database")
	decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt the Database")
	flip_parser = subparsers.add_parser("flip", help="Flip Bits on the Database, flip <num_bits> bits, at location <bits_offset>")

	start_parser = subparsers.add_parser("start", help="Starts Server")
	stop_parser = subparsers.add_parser("stop", help="Stops Server")

	conn_parser = subparsers.add_parser("connect", help="Attempts to connect to Server")
	attack_parser = subparsers.add_parser("attack", help="Attacks the data file, by flipping every bit individually")

	all_subparsers = [exe_parser, status_parser, data_parser, reset_data_parser, encrypt_parser, decrypt_parser, flip_parser, start_parser, stop_parser, conn_parser, attack_parser]

	# Loop through Subparsers
	for parser in all_subparsers:

		# Adding Database to all Subparsers
		database_subparsers = parser.add_subparsers(dest="database")

		if "status" not in parser.prog and "data" not in parser.prog:
			database_subparsers.required = True

		for key, database in get_config().items():
			data_folder = database.data_folder

			subsubparser = database_subparsers.add_parser(key)

			if "reset" in parser.prog or "attack" in parser.prog:

				if "attack" in parser.prog:
					subsubparser.add_argument("encryption_type", choices=get_encryption_types(key))

				data_files = database.data_files
				if len(database.data_files) == 0:
					subsubparser.add_argument("--filename", choices=data_files, default=None, type=str)
				elif len(database.data_files) == 1:
					subsubparser.add_argument("--filename", choices=data_files, default=data_files[0], type=str)
				else:
					subsubparser.add_argument("filename", choices=data_files, type=str)

			elif "encrypt" in parser.prog:
				subsubparser.add_argument("encryption_type", choices=get_encryption_types(key))

			elif "decrypt" in parser.prog:
				subsubparser.add_argument("decryption_type", choices=get_encryption_types(key))

			elif "flip" in parser.prog or "run" in parser.prog:

				if "run" in parser.prog:
					subsubparser.add_argument("encryption_type", choices=get_encryption_types(key))

				data_files = database.data_files
				if len(database.data_files) == 0:
					subsubparser.add_argument("--filename", choices=data_files, default=None, type=str)
				elif len(database.data_files) == 1:
					subsubparser.add_argument("--filename", choices=data_files, default=data_files[0], type=str)
				else:
					subsubparser.add_argument("filename", choices=data_files, type=str)

				subsubparser.add_argument("num_bits", type=int)
				subsubparser.add_argument("bits_offset", type=int)

	argcomplete.autocomplete(parser)
	return argparser.parse_args(argv)

def main(argv:List[str]=None):
	args = get_argparser(argv)
	print(args)
	print()

	db.Database.args = args

	if args.type == "run":
		database = get_database(args.database)()
		database.run(num_bits=args.num_bits, bits_offset=args.bits_offset, file=args.filename)
		return

	if args.type == "status":
		if args.database is None:
			databases = [get_database(database=database_key) for database_key in get_database()]
		else:
			databases = [get_database(database=args.database)]
		
		for DB in databases:
			database = DB()
			database.status()
		return

	if args.type == "data":
		if args.database is None:
			databases = [get_database(database=database_key) for database_key in get_database()]
		else:
			databases = [get_database(database=args.database)]

		for DB in databases:
			database = DB()
			database.data()
		return


	if "database" not in args:
		raise ValueError("All preceeding commands require args.database to not be None")


	database_class = get_database(database=args.database)
	database: db.Database = database_class()

	if args.type == "attack":
		database.attack(nbytes=114688, file=args.filename)

	elif args.type == "flip":
		database.flip(num_bits=args.num_bits, bits_offset=args.bits_offset, file=args.filename)

	elif args.type == "reset":
		database.reset_data(file=args.filename)

	elif args.type == "connect":
		database.connect()

	elif args.type == "start":
		database.start()

	elif args.type == "stop":
		database.close()

	elif args.type == "encrypt":	
		database.encrypt(type=args.encryption_type)

	elif args.type == "decrypt":
		database.decrypt(type=args.decryption_type)

	else:
		print(f"{args.type} not supported")
	
	
if __name__ == "__main__":
	main()

	help = """
	>>> status {mysql,postgresql,mongodb}
	Server: {MySQ,PostgreSQL,MongoDB}
	URL: <url>

	>>> start {mysql,postgresql,mongodb}
	{"port":<mysql_port:int>, ...}
	>>> stop {mysql,postgresql,mongodb}
	MySQL Server Killed, Port <port_num> is Open

	>>> encrypt {mysql,postgresql,mongodb} {mysql:{...encryption_types...},postgresql:{...encryption_types...}}
	>>> decrypt {mysql,postgresql,mongodb}

	>>> data
			col1	col2	col3	col4
	row1	....	....	....	....
	row2	....	....	....	....
	row3	....	....	....	....
	row4	....	....	....	....

	>>> flip {mysql,postgresql,mongodb} num_bits bits_offset

	>>> data
	"""


	# _b, b = 1010, int('1010',2)
	# b ^= (2 ** ( 4 + 1 ) - 1 )
	# print(_b, "->", bin(b)[2:])


	# print({6: 32, 5: 16, 4: 8, 3: 4, 2: 2, 1: 1})
	# for c, byt in zip(help, bytearray(help, "utf8")):
	# 	c = '\\n' if byt == 10 else '\\t' if byt == 9 else c
	# 	bi = bin(byt)
	# 	flipped = bin(byt^(2 ** ( len(bi) + 1 ) - 1 ))
	# 	fint = int(flipped, 2)
	# 	fc = chr(fint)
	# 	print(f"' {c:2}' {byt:3} {bi:12} -> ' {fc:2}' {fint:5} {flipped:12}")

	# print("="*56)
	# binarys = ["00110001", "11001110"]
	# for bi in binarys:
	# 	byt = int(bi, 2)
	# 	c = '\\n' if byt == 10 else '\\t' if byt == 9 else chr(byt)
	# 	flipped = bin(byt^(2 ** ( len(bi) + 1 ) - 1 ))[3:]
	# 	fint = int(flipped, 2)
	# 	fc = chr(fint)
	# 	print(f"' {c:2}' {byt:5} {bi:12} -> ' {fc:2}'\t{fint:5} {flipped:12}")

	# for c in range(0, 160):
	# 	if 157 <= c <= 160: continue
	# 	print("'"+str(c)+"'"+chr(c)+"'", end="\t")
