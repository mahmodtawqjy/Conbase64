import base64


def encrypte_pass(password):  # convert to encrypted
    encoded_bytes = base64.b64encode(password.encode())
    print(encoded_bytes)


def decrypte_pass(de_password):  # convert to decrypted
    decoded_bytes = base64.b64decode(de_password.encode())
    decode_data = decoded_bytes.decode()
    print(f"Decode Password is: {decode_data}")


while True:
    choice = input("Select 'E' to encrypt the password or 'D' to decrypt it: ")

    if choice.lower() == "e":
        password = input("Please enter your encrypte password: ")
        encrypte_pass(password)
    elif choice.lower() == "d":
        password = input("Please enter your decrypte password: ")
        decrypte_pass(password)
    else:
        print("Invalid option. Please select 'E' or 'D'.")
