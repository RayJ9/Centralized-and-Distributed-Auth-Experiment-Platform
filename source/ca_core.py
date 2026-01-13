from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import datetime

CURVE = ec.SECP256R1()

class CACore:
    @staticmethod
    def generate_private_key():
        return ec.generate_private_key(CURVE)

    @staticmethod
    def serialize_private_key(private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def load_private_key(pem_data):
        return serialization.load_pem_private_key(pem_data, password=None)

    @staticmethod
    def create_self_signed_cert(private_key, common_name="Root CA"):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Engineering Project"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256())
        
        return cert

    @staticmethod
    def create_csr(private_key, common_name):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).sign(private_key, hashes.SHA256())
        return csr

    @staticmethod
    def sign_csr(ca_cert, ca_private_key, csr):
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(ca_private_key, hashes.SHA256())
        
        return cert

    @staticmethod
    def serialize_cert(cert):
        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def save_to_file(path, data):
        with open(path, 'wb') as f:
            f.write(data)

    @staticmethod
    def load_cert_from_file(path):
        with open(path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read())

    @staticmethod
    def private_key_to_int(private_key):
        return private_key.private_numbers().private_value

    @staticmethod
    def int_to_private_key(val):
        return ec.derive_private_key(val, CURVE)
