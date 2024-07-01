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
                encrypted = (ord(char) - ascii_offset + key) % 26
                result += chr(encrypted + ascii_offset)
            else:
                decrypted = (ord(char) - ascii_offset - key) % 26
                result += chr(decrypted + ascii_offset)
        else:
            result += char
    return result

if mode == 'encrypt':
    encrypted = caesar_cipher(message, key, 'encrypt')
    print(f"Message: {message}")
    print(f"Encrypted: {encrypted}")
else:
    decrypted = caesar_cipher(message, key, 'decrypt')
    print(f"Message: {message}")
    print(f"Dencrypted: {decrypted}")

