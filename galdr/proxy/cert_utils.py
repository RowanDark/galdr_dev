# Galdr Certificate Utilities
# This module handles the generation of a root CA and on-the-fly server certificates
# for the purpose of MITM interception of HTTPS traffic.

from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

# Define paths for the CA certificate and key
CA_DIR = Path.home() / ".galdr" / "ca"
CA_CERT_PATH = CA_DIR / "galdr_ca.pem"
CA_KEY_PATH = CA_DIR / "galdr_ca_key.pem"

def get_ca_certificate():
    """
    Loads the CA certificate from disk.
    If it doesn't exist, it will be generated.
    """
    if not CA_CERT_PATH.exists() or not CA_KEY_PATH.exists():
        generate_ca()

    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    return ca_cert, ca_key

def generate_ca():
    """
    Generates and saves a new root CA certificate and private key.
    """
    print("Generating new Galdr Root CA...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save the private key
    with open(CA_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Generate the certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Galdr"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"GaldrProxy"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Galdr Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Galdr Root CA"),
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
        # Certificate valid for 10 years
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())

    # Save the certificate
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"CA certificate and key saved to {CA_DIR}")

def generate_server_certificate(hostname, ca_cert, ca_key):
    """
    Generates a new server certificate for the given hostname, signed by the CA.
    Returns the file paths to the new certificate and its private key.
    """
    print(f"Generating certificate for {hostname}...")

    # Create a directory for this specific host's cert
    host_cert_dir = CA_DIR / "hosts" / hostname
    host_cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = host_cert_dir / "cert.pem"
    key_path = host_cert_dir / "key.pem"

    # For simplicity, we'll regenerate each time for now. Caching can be added later.

    # Generate private key for the server certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save the server private key
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Create the certificate
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Certificate valid for 1 year
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(hostname)]),
        critical=False,
    ).sign(ca_key, hashes.SHA256())

    # Save the server certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated certificate for {hostname} at {cert_path}")
    return str(cert_path), str(key_path)

# Ensure the CA directory exists
CA_DIR.mkdir(parents=True, exist_ok=True)
