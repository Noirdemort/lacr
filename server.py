from flask import Flask, request, session
import os
import base64
from werkzeug.utils import secure_filename
import socket
# from OpenSSL import SSL

# context = SSL.Context(SSL.TLSv1_2_METHOD)
# context.use_privatekey_file('key.pem')
# context.use_certificate_file('cert.pem')

app = Flask(__name__)
app.secret_key = os.urandom(24)
user_dict = {}
user_file = {}

def random_salt():
    iv = os.urandom(64)
    return str(int.from_bytes(iv, byteorder="big"))

@app.route("/saveKey", methods=["POST"])
def first_contact():
    username = dict(request.form)["username"]
    if username in user_dict:
        return "1", 400
    
    user_dict[username] = []
    user_file[username] = []
    f = request.files["publicKey.pem"]
    f.save("tmp_payloads/" + secure_filename(f"{username}.pem"))
    session['username'] = username
    return "done", 200


@app.route("/getPeers")
def return_peers():
    return "BREAK:POINT".join(list(user_dict.keys()))


@app.route("/establishConnection", methods=["POST"])
def send_public_key():
    uid = dict(request.form)["client"]
    with open("tmp_payloads/" + secure_filename(f"{uid}.pem")) as f:
        return f.read()


@app.route("/messageDeploy", methods=["POST"])
def distribute_message():
    data = dict(request.form)
    uid = data["recipient"]
    msg = data["message"]
    user_dict[uid].append(msg)
    return "gotThatOne", 200


@app.route("/isThereAMessage")
def is_there_a_message():
    uid = dict(request.form)["username"]
    if uid not in user_dict:
        return "0", 402
    if not user_dict[uid]:
        return "1", 400
    return "1", 200


@app.route("/getMyLast", methods=["GET"])
def poll_messages():
    uid = dict(request.form)["username"]
    msg = user_dict[uid]
    if not msg:
        return "2", 400
    user_dict[uid] = []
    return 'BREAK#HERE'.join(msg), 200


@app.route("/filePayload", methods=["POST"])
def get_file():
    data = dict(request.form)
    uid = data["recipient"]
    author = data["author"]
    file = data["filename"]
    f = request.files["upload_file"]
    filename = secure_filename(f"{uid}-{author}-{file}")
    f.save("tmp_payloads/" + filename)
    user_file[uid].append(filename)
    return "gotThatOne", 200


@app.route("/checkPayload")
def check_file():
    uid = dict(request.form)["username"]
    if uid not in user_file:
        return "0", 402
    if not user_file[uid]:
        return "1", 400
    return "1", 200


@app.route("/getPayload", methods=["GET"])
def send_payload():
    uid = dict(request.form)["username"]
    files = user_file[uid]
    if not files:
        return "2", 400
    filename = files[0]
    text = open("tmp_payloads/" + files[0], 'rb').read()
    text = base64.b64encode(text)
    os.system(f'rm tmp_payloads/{files[0]}')
    del files[0]
    user_file[uid] = files
    return text.decode()+'FILEBREAK'+filename, 200


@app.route("/delete/<ida>", methods=["POST"])
def delete_user(ida):
    del user_dict[ida]
    for f in user_file[ida]:
        os.system(f"rm tmp_payloads/{f}")
    del user_file[ida]
    return "done"


if __name__=='__main__':
    port = int(os.environ.get('PORT', 5000))
    # app.run(host='127.0.0.1', port=port, ssl_context=('cert.pem', 'key.pem'))
    app.run(host='127.0.0.1', port=port)