#create a function
mode = input("Enter the mode(encrypt/ decrypt): ")
message = input("Enter the message: ")
key = int(input("Enter the key(1 - 26): "))
def caesar_cipher(text, key, mode):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            if mode == "encrypt":
                shifted = (ord(char) - ascii_offset + key) % 26
            else:
                shifted = (ord(char) - ascii_offset - key) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result

encrypted = caesar_cipher(message, key, 'encrypt')
print(f"Encrypted: {encrypted}")

decrypted = caesar_cipher(encrypted, key, 'decrypt')
print(f"Dencrypted: {decrypted}")

