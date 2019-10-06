import sys
import os
import pathlib
from pathlib import Path
import select
from threading import Thread
import requests
import polling

from clint.textui import colored  # printing colored text
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def gen_keys():
    '''os.system("mkdir -p $HOME/.winds")
    os.system("openssl genrsa -out $HOME/.winds/private.pem 4096")
    os.system(
        "openssl rsa -in $HOME/.winds/private.pem -outform PEM -pubout -out $HOME/.winds/public.pem"
    )'''
    with open(home + "/.winds/private.pem", "r") as file:
        private_key = file.read()
    print(colored.green("[+] Keys Generated successfully!"))
    return private_key


def upload_keys(username, i):
    '''
		Upload keys to the server
		:return username : str
    '''
    with open(home + "/.winds/public.pem", "r") as f:
        r = requests.post(f"http://{server}:{port}/saveKey", files={"publicKey.pem": f}, data={"username": username},)
        if r.status_code == 200:
            print(colored.green("[+] Public Keys Added to server!!"))
            return username
        elif r.status_code == 400 and i != 0:
            print(colored.yellow("[?] Username already exists!!"))
            username = input("Updated username: ").strip()
            if not username:
                print(colored.red("[!] Username is required."))
                exit(1)
            username = upload_keys(username, i - 1)
            return username
        else:
            print(colored.red("[!] Error in uploading public key!!"))
            exit(1)


def get_client_list(server, port):
    r = requests.get(f"http://{server}:{port}/getPeers")
    return list(r.text.split("BREAK:POINT"))


def select_client(server, port):
    client_list = get_client_list(server, port)

    idx = 1

    for client in client_list:
        print(f"{idx}. {client}")
        idx += 1

    selected_client = input("[*] Enter client id: >> ").strip()
    if selected_client == "r" or not selected_client:
        return select_client(server, port)
    
    selected_client = int(selected_client)
    if int(selected_client) > idx:
        print(colored.red("[!] Invalid Index"))
        exit(1)

    username = client_list[selected_client-1]
    r = requests.post(
        f"http://{server}:{port}/establishConnection", data={"client": username}
    )

    if r.status_code == 200:
        return r.text, username
    else:
        print(colored.yellow("[!] Didn't find the username"))
        exit(1)


def encrypt(public_key, message):
    key = RSA.import_key(public_key)
    cipherKey = PKCS1_OAEP.new(key)
    encrypted_blocks = []
    for i in range(0, len(message), 128):
        msg = message[i : i + 128]
        encrypted_data = cipherKey.encrypt(msg.encode())
        encrypted_blocks.append(intArrayToStr(encrypted_data))
    return "BREAK:HERE".join(encrypted_blocks)


def decrypt(private_key, encrypted_string):
    if not encrypted_string:
        print(colored.yellow("Found Empty."))
        return
    encrypted_units = encrypted_string.split("BREAK#HERE")
    key = RSA.import_key(private_key)
    cipherKey = PKCS1_OAEP.new(key)
    for encrypted_blocks in encrypted_units:
        clearText = ""
        encrypted_blocks = encrypted_blocks.split("BREAK:HERE")
        for block in encrypted_blocks:
            block = bytes(strToIntArray(block))
            decrypted_data = cipherKey.decrypt(block).decode()
            clearText += decrypted_data
        msg, owner =  clearText.split("USER:BREAK")
        print(f"{colored.red(owner)}: {colored.green(msg)}")


def strToIntArray(arr):
    arr = arr.split(",")
    return [int(x) for x in arr]


def intArrayToStr(arr):
    return ",".join([str(x) for x in arr])


def send_message(message, friend, public_key, username):
    enc = encrypt(public_key, message+"USER:BREAK"+username)
    r = requests.post(
        f"http://{server}:{port}/messageDeploy",
        data={"recipient": friend, "message": enc},
    )
    if r.status_code == 200:
        print(colored.green(f"You >> {message}"))
    else:
        print(colored.red(f"You >> {message} : Some Error Occured"))
        

def resp(response):
    if response == True:
        msg = requests.get(f'http://{server}:{port}/getMyLast', data= {'username': username}).text
        decrypt(private_key, msg)


def recv_msgs(arg):
    if arg():
        exit(0)
    polling.poll(
             lambda: requests.get(f'http://{server}:{port}/isThereAMessage', data={'username': username}).status_code == 200,
             check_success=resp,
             step=2,
             poll_forever=True)
           


if len(sys.argv) < 3:
    print(colored.yellow("Usage: python cli.py <server_ip> (127.0.0.1) <port> (5000)"))
    exit(0)

server = sys.argv[1]
port = int(sys.argv[2])

home = str(Path.home())
private_key = gen_keys()

username = input("Enter username: ").strip()
if not username:
    print(colored.red("[!] Username is required"))
    exit(1)

username = upload_keys(username, 1)
public_key, friend = select_client(server, port)

stop = False
thread = Thread(target = recv_msgs, args =(lambda: stop, ))
thread.start()


while 1:
    message = input(colored.cyan(f"[{friend}:] >>> ")).strip()
    
    if message == ":change":
        public_key, friend = select_client(server, port)
        
    elif message == ":get":
        msg = requests.get(f'http://{server}:{port}/getMyLast', data= {'username': username}).text
        decrypt(private_key, msg)
        
    elif message == ":q":
        requests.post(f"http://{server}:{port}/delete/{username}")
        stop = True
        thread.join()
        exit(0)
        
    elif not message:
        continue
    
    else:
        send_message(message, friend, public_key, username)
        print()
