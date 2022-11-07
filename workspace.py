import os
import hashlib
import getpass
from Crypto.Cipher import Blowfish
from struct import pack
import time


def main():
    if not os.path.exists("workspaces"):
        os.mkdir("workspaces")

    workspace_name = hashlib.sha512("montana".encode('utf-8')).hexdigest()
    workspace_name = hashlib.sha512(input("Enter the name of your workspace: ").encode('utf-8')).hexdigest()
    workspace_path = os.path.join("workspaces", workspace_name)

    if not os.path.exists(workspace_path):
        create_workspace = input("This workspace does not exist yet. Do you want to create it? (y/n) ")
        if create_workspace == "y":
            os.mkdir(workspace_path)
        else:
            print("No workspace found")
            exit(1)

    workspace_pwd = getpass.getpass("Enter workspace password: ")
    workspace_pwd = hashlib.sha256(workspace_pwd.encode('utf-8')).digest()

    print("Decrypting workspace files...")
    decrypt_folder(workspace_path, workspace_pwd)
    print("Decrypted all files")

    try:
        while True:
            time.sleep(1)
            pass
    except:
        print("Encrypting workspace files...")
        encrypt_folder(workspace_path, workspace_pwd)
        print("Encrypted all files")


def decrypt_folder(workspace_path, workspace_pwd: bytes):
    for file in os.listdir(workspace_path):
        decrypt_file(os.path.join(workspace_path, file), workspace_pwd)


def decrypt_file(enc_file_path, workspace_pwd: bytes):
    if os.path.isfile(enc_file_path):
        try:
            ifile_stream = open(enc_file_path, "rb")
            enc_content = ifile_stream.read()
            ifile_stream.close()

            if enc_content[:5] != b"WSBF0": # Check if file is encrypted by this script
                return

            # Get file hash
            original_file_hash = enc_content[5:69]

            # Get salt
            cipher_text = enc_content[69:]
            iv = cipher_text[:8]
            cipher_text = cipher_text[8:]
    
            cipher = Blowfish.new(workspace_pwd, Blowfish.MODE_CBC, iv)
            msg = cipher.decrypt(cipher_text)

            last_byte = msg[-1]
            msg = msg[:- (last_byte if type(last_byte) is int else ord(last_byte))]
            new_file_hash = hashlib.sha512(msg).digest()

            if original_file_hash == new_file_hash: # Check for successfull decryption
                ofile_stream = open(enc_file_path, "wb")
                ofile_stream.write(msg)
                ofile_stream.close()

        except PermissionError:
            print(f"Failed to decrypt file. {enc_file_path}. Invalid permissions")
    elif os.path.isdir(enc_file_path):
        decrypt_folder(enc_file_path, workspace_pwd)


def encrypt_folder(workspace_path, workspace_pwd: bytes):
    for file in os.listdir(workspace_path):
        encrypt_file(os.path.join(workspace_path, file), workspace_pwd)


def encrypt_file(enc_file_path, workspace_pwd: bytes):
    if os.path.isfile(enc_file_path):
        try:
            ifile_stream = open(enc_file_path, "rb")
            dec_content = ifile_stream.read()
            ifile_stream.close()

            if dec_content[:5] == b"WSBF0": # Check if file is already encrypted by this script
                return

            cipher = Blowfish.new(workspace_pwd, Blowfish.MODE_CBC)

            # Pad + encrypt content
            padding_length = 8 - len(dec_content) % 8
            padding = [padding_length]*padding_length
            padding = pack('b'*padding_length, *padding)
            msg = cipher.iv + cipher.encrypt(dec_content + padding)

            # Get original file hash
            dec_hash = hashlib.sha512(dec_content).digest()

            # Write output
            ofile_stream = open(enc_file_path, "wb")
            ofile_stream.write(b'WSBF0' + dec_hash + msg)
            ofile_stream.close()

        except PermissionError:
            print(f"Failed to encrypt file. {enc_file_path}. Invalid permissions")

    elif os.path.isdir(enc_file_path):
        encrypt_folder(enc_file_path, workspace_pwd)


if __name__ == "__main__":
    main()