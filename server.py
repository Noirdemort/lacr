from flask import Flask, request, session
import os
from werkzeug.utils import secure_filename
import socket
# from OpenSSL import SSL

# context = SSL.Context(SSL.TLSv1_2_METHOD)
# context.use_privatekey_file('key.pem')
# context.use_certificate_file('cert.pem')

app = Flask(__name__)
app.secret_key = os.urandom(24)
user_dict = {}


@app.route("/saveKey", methods=["POST"])
def first_contact():
    username = dict(request.form)["username"]
    if username in user_dict:
        return "1", 400
    
    user_dict[username] = []
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


@app.route("/delete/<ida>", methods=["POST"])
def delete_user(ida):
    del user_dict[ida]
    return "done"


if __name__=='__main__':
    port = int(os.environ.get('PORT', 5000))
    # app.run(host='127.0.0.1', port=port, ssl_context=('cert.pem', 'key.pem'))
    app.run(host='127.0.0.1', port=port)