from . import keys_bp, jsonify, request, app, json
from flask import g
from application.model import db, BaseHelper
from application.helper import tools, crypt, gcloud_kms
from application.messages import _MSG_ERR404, _MSG_ERR500, _MSG_NOPARAMS, _MSG_KEYS01, _MSG_KEYS02

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64decode

from flask_cors import cross_origin


@keys_bp.route("/keys/generate", methods=["POST"])
@cross_origin(supports_credentials=True)
def webkeys_generate():
    _djson = request.get_json()

    if "token" in _djson:
        key_pair = RSA.generate(2048)
        pri_key = key_pair.exportKey().decode()
        pub_key = key_pair.publickey().exportKey().decode()

        dkeys = {"token": _djson["token"], "pub_key": gcloud_kms.encrypt_symmetric(pub_key),
                 "pri_key": gcloud_kms.encrypt_symmetric(pri_key)}
        rkeys = BaseHelper.query(BaseHelper.generate_insert_placeholder(
            'hash.hkeys', dkeys.keys()), dkeys)
        if rkeys.rowcount > 0:
            dict_rst = {"code": 200, "message": "OK", "pubk": tools.encode_b64(pub_key)}
        else:
            dict_rst = {"code": 500, "message": _MSG_ERR500}
    else:
        dict_rst = {"code": 100, "message": _MSG_NOPARAMS}
    return jsonify(dict_rst)


@keys_bp.route("/keys/decrypt-secret", methods=["POST"])
@cross_origin(supports_credentials=True)
def webkeys_decrypt():
    _djson = request.get_json()

    if set(('message', 'token')) == set(_djson):
        g.exclude_log = {"route": "/web-keys/decrypt-secret", "attr_exclude": ["message"]}

        token = _djson['token']
        message = _djson['message']

        qhk = "SELECT pri_key FROM hash.hkeys WHERE token=:tk ORDER BY created_at DESC"
        rhk = BaseHelper.get_one(qhk, {"tk": token})

        if rhk is not None:
            try:
                key = RSA.importKey(gcloud_kms.decrypt_symmetric(b64decode(rhk["pri_key"])))
                cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
                decrypted_message = cipher.decrypt(b64decode(message)).decode()
                dict_rst = {"code": 200, "message": "OK", "decrypted": decrypted_message}
            except Exception:
                dict_rst = {"code": 500, "message": _MSG_KEYS01}
        else:
            dict_rst = {"code": 404, "message": _MSG_ERR404}
    else:
        dict_rst = {"code": 100, "message": _MSG_NOPARAMS}
    return jsonify(dict_rst)


@keys_bp.route("/kms/encrypt", methods=["POST"])
@cross_origin(supports_credentials=True)
def kms_encrypt_symmetric():
    """
    Return b64 encoded
    """
    _djson = request.get_json()
    if 'plaintext' in _djson:
        g.exclude_log = {"route": "/kms/encrypt", "attr_exclude": ["plaintext"]}
        try:
            encrypted = gcloud_kms.encrypt_symmetric(_djson["plaintext"])
            dict_rst = {"code": 200, "message": "OK", "encrypted": encrypted}
        except Exception:
            dict_rst = {"code":500, "message":_MSG_KEYS02}
    else:
        dict_rst = {"code": 404, "message": _MSG_NOPARAMS}
    return jsonify(dict_rst)


@keys_bp.route("/kms/decrypt", methods=["POST"])
@cross_origin(supports_credentials=True)
def kms_decrypt_symmetric():
    """
    Return plaintext
    """
    _djson = request.get_json()
    if 'b64' in _djson:
        g.exclude_log = {"route": "/kms/decrypt", "attr_exclude": ["b64"]}
        try:
            plaintext = gcloud_kms.decrypt_symmetric(b64decode(_djson["b64"]))
            dict_rst = {"code": 200, "message": "OK", "plaintext": plaintext}
        except Exception:
            dict_rst = {"code": 500, "message": _MSG_KEYS01}
    else:
        dict_rst = {"code": 404, "message": _MSG_NOPARAMS}
    return jsonify(dict_rst)
