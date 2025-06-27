import os
import shutil
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Paths
cs_cert_dir = os.path.join("central_system", "certs")
cp_cert_dir = os.path.join("charge_point", "certs")
os.makedirs(cs_cert_dir, exist_ok=True)
os.makedirs(cp_cert_dir, exist_ok=True)

# CA key/cert paths
ca_key_path = os.path.join(cs_cert_dir, "ca.key")
ca_cert_path = os.path.join(cs_cert_dir, "ca.crt")

# Server key/cert paths
server_key_path = os.path.join(cs_cert_dir, "server.key")
server_cert_path = os.path.join(cs_cert_dir, "server.crt")

# Client (charge point) key/cert paths
client_key_path = os.path.join(cp_cert_dir, "client.key")
client_cert_path = os.path.join(cp_cert_dir, "client.crt")

# Generate CA key
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open(ca_key_path, "wb") as f:
    f.write(ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    )

# Generate CA cert
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1825))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)
with open(ca_cert_path, "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

# Generate server key
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open(server_key_path, "wb") as f:
    f.write(server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    )

# Generate server CSR
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
    .sign(server_key, hashes.SHA256())
)

# Sign server cert with CA
server_cert = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
    .sign(ca_key, hashes.SHA256())
)
with open(server_cert_path, "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))

# Generate client (charge point) key
client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open(client_key_path, "wb") as f:
    f.write(client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    )

# Generate client CSR
client_csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "chargepoint-client")]))
    .sign(client_key, hashes.SHA256())
)

# Sign client cert with CA
client_cert = (
    x509.CertificateBuilder()
    .subject_name(client_csr.subject)
    .issuer_name(subject)
    .public_key(client_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
    .sign(ca_key, hashes.SHA256())
)
with open(client_cert_path, "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.PEM))

# Copy CA cert to charge_point/certs/ca.crt
dest_ca_cert_path = os.path.join(cp_cert_dir, "ca.crt")
shutil.copyfile(ca_cert_path, dest_ca_cert_path)

print("Certificates generated successfully in central_system/certs/ and charge_point/certs/")
print(" - Server: server.crt, server.key, ca.crt in central_system/certs/")
print(" - Charge Point: client.crt, client.key, ca.crt in charge_point/certs/")