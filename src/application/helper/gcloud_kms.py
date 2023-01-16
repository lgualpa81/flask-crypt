# Import the client library.
from google.cloud import kms
from flask import current_app as app

# Import base64 for printing the ciphertext.
import base64
def encrypt_symmetric(plaintext):
    """
    Encrypt plaintext using a symmetric key.

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        plaintext (string): message to encrypt

    Returns:
        bytes: Encrypted ciphertext.

    """

    # Convert the plaintext to bytes.
    plaintext_bytes = plaintext.encode('utf-8')

    # Create the client.
    client = kms.KeyManagementServiceClient.from_service_account_file(app.config["GKMS_KEY"])
    # Build the key name.
    key_name = client.crypto_key_path(app.config["KMS_PJ_ID"], app.config["KMS_LOCATION"], app.config["KMS_KEY_RING_ID"], app.config["KMS_KEY"])

    # Call the API.
    encrypt_response = client.encrypt(key_name, plaintext_bytes) #retorna 2 objetos (name, ciphertext)
    #name: "projects/my-project/locations/us-central1/keyRings/hkeys/cryptoKeys/paybutton-db/cryptoKeyVersions/1"
    #ciphertext: "\n$\000\356\276\231\252\324\357\022G+\000\003\177\243K\313\357(q\230\204D\3145\021\355\335u\2378\350\356W\r\r\273\0223\000\344\024\353\\U2\277.D\301V\251\256\370\001D\'\244\332U\001\356\357\007CG?\233\004\263\345\235\207|\252\014\312M\270?\260&\211\373\n\356\204f\303\363"

    #print('Ciphertext: {}'.format(base64.b64encode(encrypt_response.ciphertext)))
    return base64.b64encode(encrypt_response.ciphertext).decode()
    #return encrypt_response.ciphertext


def decrypt_symmetric(ciphertext):
    """
    Decrypt the ciphertext using the symmetric key

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        ciphertext (bytes): Encrypted bytes to decrypt.

    Returns:
        DecryptResponse: Response including plaintext.

    """

    # Create the client.
    client = kms.KeyManagementServiceClient.from_service_account_file(app.config["GKMS_KEY"])

    # Build the key name.
    key_name = client.crypto_key_path(app.config["KMS_PJ_ID"], app.config["KMS_LOCATION"], app.config["KMS_KEY_RING_ID"], app.config["KMS_KEY"])

    # Call the API.
    decrypt_response = client.decrypt(key_name, ciphertext)
    #print('Plaintext: {}'.format(decrypt_response.plaintext))
    return decrypt_response.plaintext.decode()