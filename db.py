from copy import deepcopy
from email.policy import default
import sys
from typing import List, Dict, Callable, Any, Tuple
from abc import ABC, abstractmethod, abstractproperty
import os, shutil
import time

def on_execution(func):
	
	def wrap(name):
		# TODO: replace 50 with columns from "columns, lines = os.get_terminal_size()"
		n = int(50 - len(name))
		l = n // 2
		r = l if n % 2 == 0 else l + 1
		return "=" * l + ' ' + name + ' ' + "=" * r
		
	def function_wrapper(*args, **kwargs):
		silent = kwargs.pop("silent", None)

		if not silent:
			print(wrap('Open ' + func.__name__))
		
		resp = func(*args, **kwargs)

		if not silent:
			print(wrap('End ' + func.__name__))
			print()

		return resp

	return function_wrapper


# Database Classes
class Database(ABC):
	args = None

	encryptions = []
	data_folder = ""
	data_files = []

	def __init__(self, name:str, port:int, host:str, data_folder:str, filename:str=None):
		self.name = name
		self.port = port
		self.host = host
		
		self.data_folder = data_folder
		# assert os.path.isdir(data_folder)
		self.filename = "" if filename is None else filename

		self._status = None
		self.encryption_type = None

		# To Implement
		self.encryption_methods: Dict[str, Callable] = {}
		self.decryption_methods: Dict[str, Callable] = {}

		if self.args is not None and "encryption_type" in self.args:
			self.encryption_type = self.args.encryption_type


	def data_file(self, file:str=None, folder:str=None):
		if file is None and self.filename is None:
			raise ValueError("file is None")
		
		if folder is None and self.data_folder is None:
			raise ValueError("folder is None")

		return f"{folder if folder else self.data_folder}\{file if file else self.filename}"

	@property
	def url(self, secure=False):
		return f"http{'s' if secure else ''}://{self.host}:{self.port}"
	
	@abstractmethod
	def start(self):
		"""
		Get Everything setup for this Run
		- Start MySQL80
		"""
		return True

	@abstractmethod
	def connect(self):
		pass

	@abstractmethod
	def close(self):
		pass
		
	@abstractproperty
	def is_connected(self):
		pass
	
	def encrypt(self):
		encryption_method = self.encryption_methods.get(self.encryption_type)
		encryption_method()

	def decrypt(self):
		decryption_method = self.decryption_methods.get(self.encryption_type)
		decryption_method()

	@staticmethod
	def display_data(name:str, data: List[List[Any]], headers: List[str], rows=5, cols=5):
		print(name, "data")

		for i, header in enumerate(headers):
			if i > cols: break
			print(header if i == 0 else "{:10}".format(header), end="\t")
		print()

		for i, row in enumerate(data):
			if i > rows: break
			for j, col in enumerate(row):
				if j > cols: break
				print(col if j == 0 else "{:10}".format(str(col).strip()), end="\t")
			print()
		
		print()

	@abstractmethod
	def data(self, header:str="", encrypted:bool=False):
		pass

	@abstractmethod
	def reset_data(self, file:str=None):
		"""
		Run at end because it just prints
		- Drop Database es
		- Add Data
			- Create Database es
			- Create Table main
			- Insert Data
		"""
		print(f"Reseting {{{self.name}}} Data")
	
	def run(self, num_bits:int, bits_offset:int, file:str=None, attacking=False):
		# ==================================================
		
		start_status = 1  # self.start()

		while start_status == 1:
			self.close()
			self.reset_data(file=file)		
			start_status = self.start()

		self.reset_data(file=file)

		self.connect()
		self.status()

		# ==================================================

		self.data("Original Reset Data:  ")

		self.encrypt()
		self.data("Encrypted Data:  ", encrypted=True)

		# ==================================================

		time.sleep(2)
		close_status = self.close()
		assert close_status == 0, f"MySQL80 not properly closed ({close_status} == 0)"

		# ==================================================

		self.flip(
			num_bits=num_bits,
			bits_offset=bits_offset,
			file=file,
			print_data=False)

		# ==================================================
		# We want it to start again
		# ==================================================

		restart_status = self.start()

		# if attacking:
		# 	if restart_status == 0:
		# 		return 0
		# 	return 1

		time.sleep(2)
		self.connect()

		# ==================================================

		self.data("Flipped Data:  ", encrypted=True)

		self.decrypt()
		self.data("Decrypted Data:  ")

		# ==================================================

		self.close()

		# ==================================================
	
	def attack(self, nbytes, file):
		"""
		I stop on 2480 for the non-encrypted table
		Encrypted: 1981, 10000-15312, 50000-50200
		"""

		worked = []
		errors = {}
		for i in range(0, nbytes):

			print("Attemting at Bit number", i)

			try:
				if 0 == self.run(num_bits=1, bits_offset=i, file=file, attacking=True):
					worked.append(i)
			except PermissionError as e:
				print(str(i)+": PermissionError", e)
				sys.exit(1234)
			except Exception as e:
				errors[i] = e

			if i % 10 == 0:
				print("Errors i's:", errors)
				print("Worked i's:", worked)

		print("Errors i's:", errors)
		print("Worked i's:", worked)



	def xor(self, a, b):
		if type(a) != type(b):
			raise ValueError('types of x and y do not match')

		if not isinstance(a, (str, int)):
			raise ValueError('parameter type is not (str or int)')

		if isinstance(a, str):
			return "".join([chr(ord(a[i]) ^ ord(b[i % len(b)])) for i in range(len(a))])

		if isinstance(a, int):
			return [ord(a[i]) ^ ord(a[i % len(a)]) for i in range(len(b))]

	def exe_flip(self, original, num_bits, bits_offset):
		byts = deepcopy(list(original))
		for i, b in zip(range(num_bits), original[bits_offset:]):
			byts[bits_offset+i] = b ^ 255
		return byts

	def flip(self, num_bits:int, bits_offset:int, file:str=None, print_data: bool=True):
		data_file = self.data_file(file)

		with open(data_file, 'rb') as rb_file:
			original = rb_file.read()

		print("="*50)
		print(f"Flipping {num_bits} bits starting at bit {bits_offset} of {len(original)}")
		print("="*50)
		print()

		byts = self.exe_flip(original, num_bits, bits_offset)
			
		# def xor(a, b):
		# 	for i in range(len(a)):
		# 		print(i, ord(a[i]), ord(b[i % len(b)]), ord(a[i]) ^ ord(b[i % len(b)]), chr(ord(a[i]) ^ ord(b[i % len(b)])), chr(20))
		# 	return "".join([chr(ord(a[i]) ^ ord(b[i % len(b)])) for i in range(len(a))])

		# print(xor("USERS", "ADMIN"))
		# print(self.xor("USERS", "ADMIN"))


		# print(byts, len(original), len(byts))
		# for o, b in zip(original, byts):
		# 	print(o, b, bin(o), bin(b), (b).bit_length(), o==b)

		# Writing Original data to flipped.<data_file>.csv
		with open(f"{data_file[:-4]}.backup.{data_file[-3:]}", 'wb') as wb_backup_file:
			wb_backup_file.write(original)


		# Get Permissions, possibly by stopping the DB
		# self.get_file_permissions()

		# Writing flipped data to <data_file>.csv
		with open(data_file, 'wb') as wb_file:
			wb_file.write(bytes(byts))

		if print_data:
			print("Flipped Data:  ")
			self.data()

	@on_execution
	def status(self):
		"""
		Name:	MySQL ...
		Port:	<number>
		URL:	http://
		Online:	{Running or Off}
		"""

		# TODO: Raise the proper errors here and explain what they are and what they mean.

		if self._status is None:
			self._status = "Disconnected" if not self.is_connected else "Connected"

		print("Name:\t\t", self.name)
		print("URL:\t\t", self.url)
		print("Status:\t\t", self._status)
		print("Encryption:\t", self.encryption_type)


"""
Data Folder: '.' or 'C:\\Users\\mcmul\\iCloudDrive\\iCloud~com~omz-software~Pythonista3\\school\\007'
File(s): ['data.csv']
"""
class FileDB(Database): # AES: 8, Fernet: None, rsa: None
	encryptions = ["fernet", "aes", "rsa"]
	data_files = ["data.csv"]
	data_folder = "."

	def __init__(self):
		super().__init__("file", None, None, ".", "data.csv")
		self.encryption_methods = {
			"fernet": self.encrypt_fernet,
			"aes": self.encrypt_AES,
			"rsa": self.encrypt_rsa}
		self.decryption_methods = {
			"fernet": self.decrypt_fernet,
			"aes": self.decrypt_AES,
			"rsa": self.decrypt_rsa}
	
	def start(self):
		return 0

	def connect(self):
		pass

	def close(self):
		return 0
	
	@property
	def is_connected(self):
		return True

	def data(self, header:str="", encrypted:bool=False):
		print(header)

		with open(self.data_file(), 'rb') as file:
			content = file.read()
		
		if encrypted and self.encryption_type == 'aes':
			iv, content = content[:16], content[16:]

		s = "".join([str(chr(b)) for b in content])
		print(s)
		print()

	def reset_data(self, file:str=None):
		with open(self.data_file(file), 'w') as f:
			f.write(
"""col1,col2,col3,col4,col5
11,12,13,14,15
21,22,23,24,25
31,32,33,34,35
41,42,43,44,45
51,52,53,54,55"""
)
		super().reset_data(file=file)

	"""
	Fernet:
		I was unable to flip a single bit and not have the cryptography.fernet.InvalidToken error not get throw
	"""
	def encrypt_fernet(self):
		from cryptography.fernet import Fernet

		# key generation
		key = Fernet.generate_key()
		
		# string the key in a file
		with open('fernet.key', 'wb') as filekey:
			filekey.write(key)
		
		# using the generated key
		fernet = Fernet(key)
		
		# opening the original file to encrypt
		with open(self.data_file(), 'rb') as file:
			original = file.read()
			
		# encrypting the file
		encrypted = fernet.encrypt(original)
		
		# opening the file in write mode and 
		# writing the encrypted data
		with open(self.data_file(), 'wb') as encrypted_file:
			encrypted_file.write(encrypted)


	def decrypt_fernet(self):
		from cryptography.fernet import Fernet

		# opening the key
		with open('fernet.key', 'rb') as filekey:
			key = filekey.read()

		# using the key
		fernet = Fernet(key)
		
		# opening the encrypted file
		with open(self.data_file(), 'rb') as enc_file:
			encrypted = enc_file.read()
		
		# decrypting the file
		decrypted = fernet.decrypt(encrypted)
		
		# opening the file in write mode and
		# writing the decrypted data
		with open(self.data_file(), 'wb') as dec_file:
			dec_file.write(decrypted)


	def encrypt_AES(self):
		from Crypto.Cipher import AES
		from Crypto.Util.Padding import pad
		""" 
		Encrypt an array of bytes using AES in Cipher Block Chaining mode
		data: array of bytes to encrypt. This will pad if needed.
		key: array of key bytes. Must be a legal AES key length.
		Return an encrypted array of bytes.
		Returned byte array layout: IV_bytes|cipher_bytes
		"""
		key = b'\xb2\x19*\xc1@\x86\x93\xc6\xba\x15\xb2@R\xe2\xe4cL\xfc5\xfa\xee\x84\xa8\xa5\xfa\xa7f\x90\x9b\xec\xb6\x9f'
		iv = b'\xa3M\x13\xde\x0c\xa3\xa0\xe1\x1c~@\xc8\xc7Z\xea8' # Using hard-coded key and iv fot a standard result

		with open('aes.key', 'wb') as filekey:
			filekey.write(key)

		cipher = AES.new(key, AES.MODE_CBC, iv)

		with open(self.data_file(), 'rb') as file:
			original = file.read()

		encrypted = iv + cipher.encrypt(pad(original, 16))  # return IV + ciphertext

		with open(self.data_file(), 'wb') as encrypted_file:
			encrypted_file.write(encrypted)  


	def decrypt_AES(self):
		from Crypto.Cipher import AES
		from Crypto.Util.Padding import pad, unpad

		with open('aes.key', 'rb') as filekey:
			key = filekey.read()

		# opening the encrypted file
		with open(self.data_file(), 'rb') as enc_file:
			encrypted = enc_file.read()

		iv, content = encrypted[:16], encrypted[16:]


		cipher = AES.new(key, AES.MODE_CBC, iv)

		decrypted = cipher.decrypt(content)

		# opening the file in write mode and
		# writing the decrypted data
		with open(self.data_file(), 'wb') as dec_file:
			dec_file.write(unpad(decrypted, 16))

	def encrypt_rsa(self):
		import rsa 

		# opening the original file to encrypt
		with open(self.data_file(), 'rb') as file:
			original = file.read()
		
		publicKey, privateKey = rsa.newkeys(1024)
		key = privateKey.save_pkcs1()

		# string the key in a file
		with open('rsa.key', 'wb') as filekey:
			filekey.write(key)

		# encrypting the file
		encrypted = rsa.encrypt(original, publicKey)
		
		# opening the file in write mode and 
		# writing the encrypted data
		with open(self.data_file(), 'wb') as encrypted_file:
			encrypted_file.write(encrypted)


	def decrypt_rsa(self):
		import rsa 

		# opening the key
		with open('rsa.key', 'rb') as filekey:
			key = filekey.read()
			key = rsa.PrivateKey.load_pkcs1(key)

		# opening the encrypted file
		with open(self.data_file(), 'rb') as enc_file:
			encrypted = enc_file.read()
		
		# decrypting the file
		decrypted = rsa.decrypt(encrypted, key)
		
		# opening the file in write mode and
		# writing the decrypted data
		with open(self.data_file(), 'wb') as dec_file:
			dec_file.write(decrypted)

"""
Data Folder: C:\ProgramData\MySQL\MySQL Server 8.0\Data\es
File: ['main.ibd']
"""
import mysql.connector
class MySQL(Database):
	encryptions = ["one", "two", "openssl"]
	data_files = ["main.ibd"]
	data_folder = "C:\ProgramData\MySQL\MySQL Server 8.0\Data\es"

	def __init__(self, filename:str=None):
		super().__init__("mysql", 3306, "localhost", "C:\ProgramData\MySQL\MySQL Server 8.0\Data\es", filename=filename)  # "C:/ProgramData/MySQL/MySQL Server 8.0/Data/es"
		self.encryption_methods = {
			"one": self.encrypt_one,
			"two": self.encrypt_two,
			"openssl": self.encrypt_openssl}
		self.decryption_methods = {
			"one": self.decrypt_one,
			"two": self.decrypt_two,
			"openssl": self.decrypt_openssl}

	@on_execution
	def start(self) -> int:

		output = os.popen("net start MySQL80 2>&1").read()

		status0 = "service was started successfully"
		if status0 in output:
			print("0: The MySQL80 "+status0)
			return 0

		status1 = "service could not be started"
		if status1 in output:
			print("1: The MySQL80 "+status1)
			return 1

		status2 = "service has already been started"
		if status2 in output:
			print("2: The MySQL80 "+status2)
			return 2

		print(output)

	def connect(self, es=True) -> Tuple[mysql.connector.MySQLConnection, mysql.connector.cursor_cext.CMySQLCursor]:
		
		try:
			if es and not os.path.exists("C:\ProgramData\MySQL\MySQL Server 8.0\Data\es"):
				raise ValueError("Will fail to connect to Database {es}, database folder has not been restored")

			cnx = mysql.connector.connect(
				database="es" if es else None, 
				user="root", password="asdfasdf", 
				host=self.host, port=self.port)

			return cnx, cnx.cursor()

		except mysql.connector.errors.ProgrammingError as e:
			self._status = e
			print(e)
			return {"success": False, "msg": e}

		except mysql.connector.errors.DatabaseError as e:
			self._status = e
			print(e)
			return {"success": False, "msg": e}

	@on_execution
	def close(self):

		output = os.popen("net stop MySQL80 2>&1").read()

		status0 = "service was stopped successfully"
		if status0 in output:
			print("0: The MySQL80 "+status0)
			return 0

		status1 = "service could not be stopped"
		if status1 in output:
			print("1: The MySQL80 "+status1)
			return 1

		status2 = "service is not started"
		if status2 in output:
			print("2: The MySQL80 "+status2)
			return 2

		print(output)

	@on_execution
	def reset_data(self, file:str=None):

		if os.path.exists(self.data_folder):
			shutil.rmtree(self.data_folder)
		if os.path.exists(self.data_folder+".backup"):
			shutil.rmtree(self.data_folder+".backup")

		conn = self.connect(es=False)

		if isinstance(conn, dict):
			return conn

		cnx, cursor = conn

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

		super().reset_data(file=file)

	@on_execution
	@property
	def is_connected(self):
		cnx, cursor = self.connect()
		if cnx is None:
			return None
		is_con = cnx.is_connected()
		cursor.close()
		cnx.close()
		return is_con


	# Abstract Methods
	@on_execution
	def data(self, header:str="", encrypted:bool=False):
		print(header, end="")

		cnx, cursor = self.connect()
		cursor.execute("select * from main;")

		Database.display_data(name=self.name, data=cursor, headers=cursor.column_names)

		cursor.close()
		cnx.close()

	# Flip
	@on_execution
	def flip(self, num_bits: int, bits_offset: int, file: str = None, print_data: bool=True):
		# return self.flip2(num_bits, bits_offset, file, print_data)
		"""
		1. Take a backup of all .ibd and .frm files.
		2. Create the database and tables using the SQL queries from the web app installation script.
		3. Delete the newly created files using the DISCARD statement. Eg. ALTER TABLE newdb.table1 DISCARD TABLESPACE;
		4. Then copy all the .ibd and .frm files from backup to the database folder, and assign mysql:mysql ownership.
		5. Ask MySQL to accept the new files using the IMPORT statement. Eg. ALTER TABLE newdb.table1 IMPORT TABLESPACE;
		"""
		data_file = self.data_file(file)
		print(data_file)

		with open(data_file, 'rb') as rb_file:
			original = rb_file.read()
			
		print(f"Flipping {num_bits} bits starting at bit {bits_offset} of {len(original)}")

		backup_folder = f"{self.data_folder}.backup"
		if not os.path.exists(backup_folder):
			os.mkdir(backup_folder)

		with open(self.data_file(file, folder=backup_folder), 'wb') as wb_backup_file:
			wb_backup_file.write(original)

		byts = self.exe_flip(original, num_bits, bits_offset)

		# Writing flipped data to <data_file>.csv
		with open(data_file, 'wb') as wb_file:
			wb_file.write(bytes(byts))


		with open(self.data_file(file, folder=backup_folder), 'rb') as rb_backup_file:
			backup = rb_backup_file.read()
		print("Backup:")
		print("".join([bin(x) for x in backup[:50]]))

		with open(data_file, 'rb') as rb_file:
			original = rb_file.read()
		print("New File:")
		print("".join([bin(x) for x in original[:50]]))


	def flip2(self, num_bits: int, bits_offset: int, file: str = None, print_data: bool=True):
		"""
		Method:
			flip2(num_bits: int, bits_offset: int, file: str = None, print_data: bool=True) -> None

		Description:
			Flips Bits without turning off the server.
			It just Discards the TABLESPACE and then re-IMPORTs it
		"""
		data_file = self.data_file()

		with open(data_file, 'rb') as rb_file:
			original = rb_file.read()

		def create(cur):
			cur.execute("CREATE DATABASE IF NOT EXISTS es;")
			cur.execute("USE es;")

			cur.execute("""
				CREATE TABLE main (
					col1 VARCHAR(50) NOT NULL,
					col2 VARCHAR(50) NOT NULL,
					col3 VARCHAR(50) NOT NULL,
					col4 VARCHAR(50) NOT NULL,
					col5 VARCHAR(50) NOT NULL);""")


		# self.start() # TEMP
		# cnx, cur = self.connect(es=False)

		# 2
		# create(cur)

		# 3
		# print("3")
		# cur.execute("ALTER TABLE es.main DISCARD TABLESPACE;")  # Should delete main.ibd

		# 4
		# FLIP BITS
		byts = self.exe_flip(original, num_bits, bits_offset)

		# 5
		# print("5")
		# cur.execute("SHOW DATABASES;")
		# for c in cur:
		# 	print(c)

		# cur.execute("DROP DATABASE IF EXISTS es;")
		
		# if os.path.exists(self.data_folder):
			# shutil.rmtree(self.data_folder)

		# create(cur)

		# cur.execute("ALTER TABLE es.main IMPORT TABLESPACE;")

	# Encryption methods
	@on_execution
	def encrypt_one(self):
		pass

	def encrypt_two(self):
		pass

	def encrypt_openssl(self):
		pass


	# Decryption methods
	@on_execution
	def decrypt_one(self):
		pass

	def decrypt_two(self):
		pass

	def decrypt_openssl(self):
		pass
		





"""
MYSQL2












Data Folder: C:\ProgramData\MySQL\MySQL Server 8.0\Data\es
File: ['main.ibd']
"""
import mysql.connector
class MySQL2(Database):
	encryptions = ["one", "two", "openssl"]
	data_files = ["main.ibd"]
	data_folder = "C:\ProgramData\MySQL\MySQL Server 8.0\Data\es"

	def __init__(self, filename:str=None):
		super().__init__("mysql", 3306, "localhost", "C:\ProgramData\MySQL\MySQL Server 8.0\Data\es", filename=filename)  # "C:/ProgramData/MySQL/MySQL Server 8.0/Data/es"
		self.encryption_methods = {
			"one": self.encrypt_one,
			"two": self.encrypt_two,
			"openssl": self.encrypt_openssl}
		self.decryption_methods = {
			"one": self.decrypt_one,
			"two": self.decrypt_two,
			"openssl": self.decrypt_openssl}

	@on_execution
	def start(self) -> int:

		output = os.popen("net start MySQL80 2>&1").read()

		status0 = "service was started successfully"
		if status0 in output:
			print("0: The MySQL80 "+status0)
			return 0

		status1 = "service could not be started"
		if status1 in output:
			print("1: The MySQL80 "+status1)
			return 1

		status2 = "service has already been started"
		if status2 in output:
			print("2: The MySQL80 "+status2)
			return 2

		print(output)

	def connect(self, es=True) -> Tuple[mysql.connector.MySQLConnection, mysql.connector.cursor_cext.CMySQLCursor]:
		
		try:
			if es and not os.path.exists("C:\ProgramData\MySQL\MySQL Server 8.0\Data\es"):
				raise ValueError("Will fail to connect to Database {es}, database folder has not been restored")

			cnx = mysql.connector.connect(
				database="es" if es else None, 
				user="root", password="asdfasdf", 
				host=self.host, port=self.port)

			return cnx, cnx.cursor()

		except mysql.connector.errors.ProgrammingError as e:
			self._status = e
			print(e)
			return {"success": False, "msg": e}

		except mysql.connector.errors.DatabaseError as e:
			self._status = e
			print(e)
			return {"success": False, "msg": e}

	@on_execution
	def close(self):

		output = os.popen("net stop MySQL80 2>&1").read()

		status0 = "service was stopped successfully"
		if status0 in output:
			print("0: The MySQL80 "+status0)
			return 0

		status1 = "service could not be stopped"
		if status1 in output:
			print("1: The MySQL80 "+status1)
			return 1

		status2 = "service is not started"
		if status2 in output:
			print("2: The MySQL80 "+status2)
			return 2

		print(output)

	@on_execution
	def reset_data(self, file:str=None):

		if os.path.exists(self.data_folder):
			shutil.rmtree(self.data_folder)
		if os.path.exists(self.data_folder+".backup"):
			shutil.rmtree(self.data_folder+".backup")

		conn = self.connect(es=False)

		if isinstance(conn, dict):
			return conn

		cnx, cursor = conn

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

		super().reset_data(file=file)

	@on_execution
	@property
	def is_connected(self):
		cnx, cursor = self.connect()
		if cnx is None:
			return None
		is_con = cnx.is_connected()
		cursor.close()
		cnx.close()
		return is_con


	# Abstract Methods
	@on_execution
	def data(self, header:str="", encrypted:bool=False):
		print(header, end="")

		cnx, cursor = self.connect()
		cursor.execute("select * from main;")

		Database.display_data(name=self.name, data=cursor, headers=cursor.column_names)

		cursor.close()
		cnx.close()

	# Flip
	@on_execution
	def flip(self, num_bits: int, bits_offset: int, file: str = None, print_data: bool=True):
		# return self.flip2(num_bits, bits_offset, file, print_data)
		"""
		1. Take a backup of all .ibd and .frm files.
		2. Create the database and tables using the SQL queries from the web app installation script.
		3. Delete the newly created files using the DISCARD statement. Eg. ALTER TABLE newdb.table1 DISCARD TABLESPACE;
		4. Then copy all the .ibd and .frm files from backup to the database folder, and assign mysql:mysql ownership.
		5. Ask MySQL to accept the new files using the IMPORT statement. Eg. ALTER TABLE newdb.table1 IMPORT TABLESPACE;
		"""
		data_file = self.data_file(file)
		print(data_file)

		with open(data_file, 'rb') as rb_file:
			original = rb_file.read()
			
		print(f"Flipping {num_bits} bits starting at bit {bits_offset} of {len(original)}")

		backup_folder = f"{self.data_folder}.backup"
		if not os.path.exists(backup_folder):
			os.mkdir(backup_folder)

		with open(self.data_file(file, folder=backup_folder), 'wb') as wb_backup_file:
			wb_backup_file.write(original)

		byts = self.exe_flip(original, num_bits, bits_offset)

		# Writing flipped data to <data_file>.csv
		with open(data_file, 'wb') as wb_file:
			wb_file.write(bytes(byts))


		with open(self.data_file(file, folder=backup_folder), 'rb') as rb_backup_file:
			backup = rb_backup_file.read()
		print("Backup:")
		print("".join([bin(x) for x in backup[:50]]))

		with open(data_file, 'rb') as rb_file:
			original = rb_file.read()
		print("New File:")
		print("".join([bin(x) for x in original[:50]]))


	def flip2(self, num_bits: int, bits_offset: int, file: str = None, print_data: bool=True):
		"""
		Method:
			flip2(num_bits: int, bits_offset: int, file: str = None, print_data: bool=True) -> None

		Description:
			Flips Bits without turning off the server.
			It just Discards the TABLESPACE and then re-IMPORTs it
		"""
		data_file = self.data_file()

		with open(data_file, 'rb') as rb_file:
			original = rb_file.read()

		def create(cur):
			cur.execute("CREATE DATABASE IF NOT EXISTS es;")
			cur.execute("USE es;")

			cur.execute("""
				CREATE TABLE main (
					col1 VARCHAR(50) NOT NULL,
					col2 VARCHAR(50) NOT NULL,
					col3 VARCHAR(50) NOT NULL,
					col4 VARCHAR(50) NOT NULL,
					col5 VARCHAR(50) NOT NULL);""")


		# self.start() # TEMP
		# cnx, cur = self.connect(es=False)

		# 2
		# create(cur)

		# 3
		# print("3")
		# cur.execute("ALTER TABLE es.main DISCARD TABLESPACE;")  # Should delete main.ibd

		# 4
		# FLIP BITS
		byts = self.exe_flip(original, num_bits, bits_offset)

		# 5
		# print("5")
		# cur.execute("SHOW DATABASES;")
		# for c in cur:
		# 	print(c)

		# cur.execute("DROP DATABASE IF EXISTS es;")
		
		# if os.path.exists(self.data_folder):
			# shutil.rmtree(self.data_folder)

		# create(cur)

		# cur.execute("ALTER TABLE es.main IMPORT TABLESPACE;")

	# Encryption methods
	@on_execution
	def encrypt_one(self):
		pass

	def encrypt_two(self):
		pass

	def encrypt_openssl(self):
		pass


	# Decryption methods
	@on_execution
	def decrypt_one(self):
		pass

	def decrypt_two(self):
		pass

	def decrypt_openssl(self):
		pass
		









"""
Help: 
	https://www.postgresql.fastware.com/blog/how-postgresql-maps-your-tables-into-physical-files#:~:text=PostgreSQL%20stores%20its%20data%20files,into%20a%20number%20of%20subdirectories.

Get Data Folder:
	postgres=# select datname, oid from pg_database;
		datname  |  oid
		-----------+-------
		postgres  | 13442
		es        | 16410
		template1 |     1
		template0 | 13441

Data Folder: C:\Program Files\PostgreSQL\\13\data\\base\\16410
File: <all_files:*>
"""
class PostgreSQL(Database):
	data_files = []
	data_folder = "C:\Program Files\PostgreSQL\\13\data\\base\\16410"

	def __init__(self, filename:str=None):
		super().__init__("postgresql", 5432, "localhost", "C:\Program Files\PostgreSQL\\13\data\\base\\16410", filename=filename)

	def start(self):
		os.system('net start postgresql-x64-13')
		time.sleep(3)

	def reset_data(self, file:str=None):
		pass

	def close(self):
		os.system('net stop postgresql-x64-13')

	def connect(self):
		import psycopg2

		try:
			cnx: psycopg2.connection = psycopg2.connect(database="es", user="postgres", password="asdfasdf", host=self.host, port=self.port)
			cnx.autocommit = True
			return cnx, cnx.cursor()
		except Exception as e:
			self._status = e
			print(e)
			return None, None

	@property
	def is_connected(self):
		cnx, cursor = self.connect()
		if cnx is None:
			return None
		return not cnx.closed

	# Abstract Methods
	def data(self):
		cnx, cur = self.connect()
		cur.execute("select * from main;")
		Database.display_data(name=self.name, data=cur, headers=[desc[0] for desc in cur.description])


"""
Data Folder: C:\Program Files\MongoDB\Server\\4.4\data
Files: ['collection-0--2071981473267814096.wt', 'index-1--2071981473267814096.wt']
"""
class MongoDB(Database):
	data_files = []
	data_folder = "C:\Program Files\MongoDB\Server\\4.4\data"

	def __init__(self, filename:str=None):
		super().__init__("mongodb", 27017, "localhost", "C:\Program Files\MongoDB\Server\\4.4\data", filename=filename)

	def start(self):
		os.system('net start MongoDB')
		time.sleep(3)

	def reset_data(self, file:str=None):
		pass

	def close(self):
		os.system('net stop MongoDB')

	def connect(self):
		import pymongo

		try:
			cnx = pymongo.MongoClient(host=self.host, port=self.port)
			# user="postgres", password="asdfasdf"
			return cnx, None
		except Exception as e:
			self._status = e
			print(e)
			return None, None

	@property
	def is_connected(self):
		cnx, _ = self.connect()
		if cnx is None:
			return None
		return cnx.admin.command('ismaster')['ismaster']

	# Abstract Methods
	def data(self):
		cnx, _ = self.connect()

		main = cnx['es']['main']

		def trim(r: Dict):
			r.pop("_id")
			return list(r.values())

		data = [trim(row) for row in main.find()]
		headers = list(main.find_one().keys())[1:]
		Database.display_data(name=self.name, data=data, headers=headers)


def get_dbs() -> Dict[str, Database] :
    return {
		"file": FileDB,
		"mysql": MySQL,
		"mysql2": MySQL2,
		"postgresql": PostgreSQL,
		"mongodb": MongoDB
	}



"""
==================== Open start ====================
0: The MySQL80 service was started successfully
==================== End start =====================

================= Open reset_data ==================
Reseting {mysql} Data
================== End reset_data ==================

=================== Open status ====================
Name:            mysql
URL:             http://localhost:3306
Encrypted:       Yes
==================== End status ====================

==================== Open data =====================
Encrypted Data:  mysql data
col1    col2            col3            col4            col5
11      12              13              14              15
21      22              23              24              25
31      32              33              34              35
41      42              43              44              45
51      52              53              54              55

===================== End data =====================

==================== Open close ====================
0: The MySQL80 service was stopped successfully
==================== End close =====================

==================== Open flip =====================
C:/ProgramData/MySQL/MySQL Server 8.0/Data/es/main.ibd
Flipping 1 bits starting at bit 35 of 114688
Backup:
0b101100110b1101010b101011100b111010b00b00b00b00b00b10b1110000b100101100b00b00b00b10b00b00b00b00b111100b11100010b111010000b11011100b00b10000b00b00b00b00b00b00b00b00b00b00b1000010b110100110b00b00b1000010b110100110b00b00b00b00b00b00b00b111
New File:
0b101100110b1101010b101011100b111010b00b00b00b00b00b10b1110000b100101100b00b00b00b10b00b00b00b00b111100b11100010b111010000b11011100b00b10000b00b00b00b00b00b00b00b00b00b111111110b1000010b110100110b00b00b1000010b110100110b00b00b00b00b00b00b00b111
===================== End flip =====================

==================== Open start ====================
0: The MySQL80 service was started successfully
==================== End start =====================

==================== Open data =====================
Flipped Data:  Traceback (most recent call last):
  File "C:/Python39/lib/site-packages/mysql/connector/connection_cext.py", line 523, in cmd_query
    self._cmysql.query(query,
_mysql_connector.MySQLInterfaceError: Tablespace is missing for table `es`.`main`.

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "C:/Users/mcmul/Documents/School/Michigan/007_EECS_598/project/main.py", line 202, in <module>
    main()
  File "C:/Users/mcmul/Documents/School/Michigan/007_EECS_598/project/main.py", line 140, in main
    database.run(num_bits=args.num_bits, bits_offset=args.bits_offset, file=args.filename)
  File "C:/Users/mcmul/Documents/School/Michigan/007_EECS_598/project/db.py", line 190, in run
    self.data("Flipped Data:  ", encrypted=True)
  File "C:/Users/mcmul/Documents/School/Michigan/007_EECS_598/project/db.py", line 24, in function_wrapper
    resp = func(*args, **kwargs)
  File "C:/Users/mcmul/Documents/School/Michigan/007_EECS_598/project/db.py", line 666, in data
    cursor.execute("select * from main;")
  File "C:/Python39/lib/site-packages/mysql/connector/cursor_cext.py", line 269, in execute
    result = self._cnx.cmd_query(stmt, raw=self._raw,
  File "C:/Python39/lib/site-packages/mysql/connector/connection_cext.py", line 528, in cmd_query
    raise errors.get_mysql_exception(exc.errno, msg=exc.msg,
mysql.connector.errors.DatabaseError: 1812 (HY000): Tablespace is missing for table `es`.`main`.
"""


# RSA
"""
Attemting at Bit number 195
Reseting {file} Data
Reseting {file} Data
=================== Open status ====================
Name:   file
URL:   http://None:None
Status:   Connected
Encryption:  rsa
==================== End status ====================

Original Reset Data:
col1,col2,col3,col4,col5
11,12,13,14,15
21,22,23,24,25
31,32,33,34,35
41,42,43,44,45
51,52,53,54,55

Encrypted Data:
D«¼¥ÂJ+%6MëY3zÊ,.°Ò¤Ö¸sk§Æ▼¹dµñ6Øìq~ûJi\»ß³F◄mKÝà&.ì)ãæñ?ç~ÀxbóRS=$◄Á~          çøs]bóRS=$◄Á~
Úç↨²ã{¾ýâ¥bÇM                         D¶°"ÙCÒOUÝ3a±uÜÄËò@    D¶°"ÙCÒOUÝ3a±uÜÄËò@
èºUåº

==================================================
Flipping 1 bits starting at bit 196 of 128
==================================================

Flipped Data:
D«¼¥ÂJ+%6MëY3zÊ,.°Ò¤Ö¸sk§Æ▼¹dµñ6Øìq~ûJi\»ß³F◄mKÝ
Úç↨²ã{
èºUåº

Decrypted Data:
col1,col2,col3,col4,col5
11,12,13,14,15
21,22,23,24,25
31,32,33,34,35
41,42,43,44,45
51,52,53,54,55
"""


# AES
# """
# ==================================================
# Flipping 1 bits starting at bit 0 of 128
# ==================================================

# Flipped Data:
# ÅÍyï°àÇxø¶
# ♥4a·ý:²ÌïùY½♦¸íTC6&°¬.Hú;i¶;ÑÉ♣G¿k
# *Ðÿþp¥XQÁbo\uBÿ*ê'É     Bp2

# Decrypted Data:
# ol1,col2,col3,col4,col5
# 11,12,13,14,15
# 21,22,23,24,25
# 31,32,33,34,35
# 41,42,43,44,45
# 51,52,53,54,55

# ==================================================
# Flipping 1 bits starting at bit 1 of 128
# ==================================================

# Flipped Data:
# ÅÍyï°àÇxø¶
# ♥4a·ý:²ÌïùY½♦¸íTC6&°¬.Hú;i¶;ÑÉ♣G¿k
# *Ðÿþp¥XQÁbo\uBÿ*ê'É     Bp2

# Decrypted Data:
# ca·ý:²ÌïùY½♦¸íTC6&°¬.Hú;i¶;ÑÉ♣G¿k
# *Ðÿþp¥XQÁbo\uBÿ*ê'É     Bp2

# ==================================================
# Flipping 1 bits starting at bit 2 of 128
# ==================================================

# Flipped Data:
# ÅÍyï°àÇxø¶
# ♥4a·ý:²ÌïùY½♦¸íTC6&°¬.Hú;i¶;ÑÉ♣G¿k
# *Ðÿþp¥XQÁbo\uBÿ*ê'É     Bp2

# Decrypted Data:
# co1,col2,col3,col4,col5
# 11,12,13,14,15
# 21,22,23,24,25
# 31,32,33,34,35
# 41,42,43,44,45
# 51,52,53,54,55
# """