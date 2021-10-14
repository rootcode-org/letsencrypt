# Copyright is waived. No warranty is provided. Unrestricted use and modification is permitted.

import ssl
import sys
import json
import time
import base64
import math
import certifi
from hashlib import sha256
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# Import non-standard modules
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
except ImportError:
    sys.exit("Requires Cryptography module; try 'pip install cryptography'")

try:
    import boto3
except ImportError:
    sys.exit("Requires Boto3 module; try 'pip install boto3'")


PURPOSE = """\
Generate a CA-signed certificate with Let's Encrypt

letsencrypt.py [bits=<n>] info=<path> key=<path> cert=<path>

where,
   bits   optional, number of bits for certificate private key (default = 2048)
   info   input path to JSON file with certificate information in X.509 naming scheme
   key    input path to Let's Encrypt account private key
   cert   output path to certificate file
"""


def urlrequest(uri, method=None, data=None, headers=None):
    request = Request(uri)
    if method:
        request.get_method = lambda: method
    if data:
        request.data = data
    if headers:
        for k, v in headers.items():
            request.add_header(k, v)
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=certifi.where())
    try:
        fp = urlopen(request, context=context)
        headers = {key.lower(): fp.headers[key] for key in fp.headers}
        return fp.code, fp.read(), headers                  # On success the response body is returned as bytes()
    except HTTPError as e:
        headers = {key.lower(): e.headers[key] for key in e.headers}
        return e.code, e.read().decode("latin_1"), headers         # On fail the response body is returned as str()
    except URLError as e:
        return 0, "URL Error", []


# Automated Certificate Management Environment
# see https://tools.ietf.org/html/rfc8555 for a description of the ACME protocol
class ACME:
    def __init__(self, account_key):
        self.service_url = "https://acme-v02.api.letsencrypt.org/directory"
        self.account_key = account_key
        self.account_url = None
        self.next_nonce = None

        # Retrieve URL's needed for service operations
        code, body, headers = urlrequest(self.service_url)
        if code != 200:
            sys.exit(body)
        self.operation_urls = json.loads(body)

        # Parse public key from the account private key
        private_key = load_pem_private_key(self.account_key.encode("latin_1"), password=None, backend=default_backend())
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        modulus = '{:x}'.format(public_numbers.n)
        exponent = public_numbers.e

        # Construct a JSON Web Key from the public key per https://tools.ietf.org/html/rfc7517#section-4
        modulus_bytes = bytearray.fromhex(modulus)
        modulus_b64 = base64.urlsafe_b64encode(modulus_bytes).rstrip(b"=")
        shift_max = int(math.log(exponent, 2)) & ~7
        exponent_bytes = [exponent >> shift & 0xff for shift in range(shift_max, -1, -8)]
        exponent_bytes = bytearray(exponent_bytes)
        exponent_b64 = base64.urlsafe_b64encode(exponent_bytes).rstrip(b"=")
        self.jwk = {"kty": "RSA", "e": exponent_b64.decode("latin_1"), "n": modulus_b64.decode("latin_1")}

        # Compute thumbprint of the JSON Web Key per https://tools.ietf.org/html/rfc7638#section-3
        jwk_string = json.dumps(self.jwk, sort_keys=True, separators=(",", ":"))
        jwk_thumbprint = sha256(jwk_string.encode("latin_1")).digest()
        self.jwk_thumbprint_b64 = base64.urlsafe_b64encode(jwk_thumbprint).rstrip(b"=")

        # Create or find the account for the provided account key
        payload = {"termsOfServiceAgreed": True}
        code, body, headers = self.send_request(self.operation_urls["newAccount"], payload)
        if code not in [200, 201]:  # 200 = Account located,  201 = Account created
            sys.exit(body)

        # Ensure the account is still valid
        response = json.loads(body)
        if response["status"] != "valid":
            sys.exit("Account is not valid")

        # Get the account URL from the response; this will be used in place of the JWK in future requests
        self.account_url = headers["location"]

    def order_certificate(self, common_name, csr_der_b64):
        payload = {
            "identifiers": [
                {"type": "dns", "value": common_name}
            ]
        }
        code, body, headers = self.send_request(self.operation_urls["newOrder"], payload)
        if code is not 201:
            sys.exit(body)
        response = json.loads(body)
        authorizations = response["authorizations"]
        finalize_url = response["finalize"]

        # There should be one authorization per common/san name in the certificate request
        dns_challenge_urls = []
        for authorization_url in authorizations:

            # Get the challenges for this authorization
            code, body, headers = self.send_request(authorization_url, None)
            if code != 200:
                sys.exit("Failed to receive authorization data")
            response = json.loads(body)
            challenges = response["challenges"]

            # Locate and perform the DNS challenge
            for challenge in challenges:
                if challenge["type"] == "dns-01":

                    challenge_token = challenge["token"]
                    challenge_url = challenge["url"]
                    dns_challenge_urls.append(challenge_url)

                    # Generate authorization token
                    token = challenge_token.encode("latin_1") + b"." + self.jwk_thumbprint_b64
                    token_hash = sha256(token).digest()
                    token_hash_b64 = base64.urlsafe_b64encode(token_hash).rstrip(b"=")

                    # Write authorization token to a TXT record in the domain DNS entry
                    route53 = boto3.client("route53")
                    response = route53.list_hosted_zones()
                    domain_name = ".".join(common_name.split(".")[-2:])
                    for zone in response["HostedZones"]:
                        if zone["Name"].rstrip(".") == domain_name:
                            zone_id = zone["Id"]
                            route53.change_resource_record_sets(
                                HostedZoneId=zone_id,
                                ChangeBatch={
                                    'Changes': [
                                        {
                                            'Action': 'UPSERT',
                                            'ResourceRecordSet': {
                                                'Name': '_acme-challenge.' + common_name,
                                                'Type': 'TXT',
                                                'TTL': 30,
                                                'ResourceRecords': [
                                                    {'Value': '\"' + token_hash_b64.decode('utf-8') + '\"'}
                                                ],
                                            }
                                        },
                                    ]
                                }
                            )

        # Give DNS some time to update
        time.sleep(40)

        # For every challenge that we completed, indicate that it's ready to be tested
        for challenge_url in dns_challenge_urls:
            code, body, headers = self.send_request(challenge_url, {})
            if code != 200:
                sys.exit("Failed to start challenge validation")

        # Poll until all authorizations have completed
        for authorization_url in authorizations:
            while True:
                code, body, headers = self.send_request(authorization_url, None)
                if code != 200:
                    sys.exit(body)
                response = json.loads(body)
                if response["status"] == "valid":
                    break
                elif response["status"] == "pending":
                    time.sleep(10)
                else:
                    sys.exit(body)

        # Finalize certificate
        payload = {"csr": csr_der_b64.decode("latin_1")}
        code, body, headers = self.send_request(finalize_url, payload)
        if code != 200:
            sys.exit(body)
        response = json.loads(body)
        certificate_url = response["certificate"]

        # Download and return certificate
        code, body, headers = urlrequest(certificate_url)
        if code != 200:
            sys.exit(body)
        return body

    def get_nonce(self):
        nonce = self.next_nonce
        self.next_nonce = None
        if not nonce:
            code, body, headers = urlrequest(self.operation_urls["newNonce"], method="HEAD")
            if code != 200:
                sys.exit("Failed to acquire a nonce")
            nonce = headers["replay-nonce"]
        return nonce

    def send_request(self, url, payload):

        # Base64 encode the payload
        payload_string = json.dumps(payload) if payload is not None else ""
        payload_b64 = base64.urlsafe_b64encode(payload_string.encode("latin_1")).rstrip(b"=")

        # Create a required 'protected header' containing the account key, a nonce value, and the requested URL
        nonce = self.get_nonce()
        protected = {"alg": "RS256", "nonce": nonce, "url": url}
        if self.account_url:
            protected["kid"] = self.account_url
        else:
            protected["jwk"] = self.jwk
        protected_string = json.dumps(protected)
        protected_b64 = base64.urlsafe_b64encode(protected_string.encode("latin_1")).rstrip(b"=")

        # Sign the request
        string_to_sign = protected_b64 + b"." + payload_b64
        private_key = load_pem_private_key(self.account_key.encode("latin_1"), password=None, backend=default_backend())
        signature = private_key.sign(string_to_sign, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")

        # Send the request
        request_data = {"protected": protected_b64.decode("latin_1"), "payload": payload_b64.decode("latin_1"), "signature": signature_b64.decode("latin_1")}
        request_data_string = json.dumps(request_data)
        request_headers = {"content-type": "application/jose+json"}
        code, body, headers = urlrequest(url, data=request_data_string.encode("latin_1"), headers=request_headers)

        # The response headers may contain a nonce value which can be used for the next request
        if "replay-nonce" in headers:
            self.next_nonce = headers["replay-nonce"]
        return code, body, headers


def generate_ca_signed_certificate(num_bits, information, acme_account_key):

    # Generate a certificate signing request
    builder = x509.CertificateSigningRequestBuilder()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, information["C"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, information["ST"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, information["L"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, information["O"]),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, information["OU"]),
        x509.NameAttribute(NameOID.COMMON_NAME, information["CN"]),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, information["EMAIL"])
    ])
    builder = builder.subject_name(subject)
    constraints = x509.BasicConstraints(ca=False, path_length=None)
    builder = builder.add_extension(constraints, critical=True)
    private_key = rsa.generate_private_key(65537, num_bits, default_backend())
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    csr_der_b64 = base64.urlsafe_b64encode(csr_der).rstrip(b"=")

    # Request certificate from Let's Encrypt
    acme = ACME(acme_account_key)
    certificate_bytes = acme.order_certificate(information["CN"], csr_der_b64)
    private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
    return private_key_bytes.decode("latin_1"), certificate_bytes.decode("latin_1")


if __name__ == '__main__':

    if sys.version_info < (3, 6):
        sys.exit("Python version must be 3.6 or later")
    if len(sys.argv) < 3:
        sys.exit(PURPOSE)

    num_bits = next((x.split("=", 1)[-1] for x in sys.argv if x.find("bits=") == 0), None)
    num_bits = int(num_bits) if num_bits else 2048
    info_path = next((x.split("=", 1)[-1] for x in sys.argv if x.find("info=") == 0), None)
    with open(info_path, "r") as f:
        info_json = json.load(f)
    key_path = next((x.split("=", 1)[-1] for x in sys.argv if x.find("key=") == 0), None)
    with open(key_path, "r") as f:
        lets_encrypt_account_key = f.read()
    cert_path = next((x.split("=", 1)[-1] for x in sys.argv if x.find("cert=") == 0), None)
    pk, cert = generate_ca_signed_certificate(num_bits, info_json, lets_encrypt_account_key)
    with open(cert_path, "w") as f:
        f.write(pk)
        f.write(cert)
    print("Certificate saved to " + cert_path)
