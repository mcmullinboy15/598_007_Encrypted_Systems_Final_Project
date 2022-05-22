import cryptography
from main import main

"""
I need to check this looping for all types of encryption
    file:
        - fernet
        - AES-256  # TODO -> https://github.com/FrugalGuy/bitflipper

    mysql:
        - 
        - 
    

"""

def file_each_bit():
    # Attempt:
    #   Flip each bit by itself and attempt to decrypt
    # Outcom:
    #   cryptography.fernet.InvalidToken error on all bits in data.csv
    #
    successful = []
    failed = []
    for i in range(228):  # length of encrypted data -> 228
        print(i)

        try:
            main(["run", "file", "1", str(i)])
            successful.append(i)
        except cryptography.fernet.InvalidToken as e:
            print(e)
            failed.append(i)

    print(successful)
    print(failed)

def file_each_bit_and_each_key_bit():
    pass


if __name__ == "__main__":
    file_each_bit()