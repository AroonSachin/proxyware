from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import subprocess
import paramiko
from datetime import datetime, timedelta


def generate_ca_certificate(cert_dir="resources/mitmproxy-ca"):
    """
    Generate a self-signed CA certificate for mitmproxy.
    """
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    print("Generating the private key for the CA certificate")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open(os.path.join(cert_dir, "ca_key.pem"), "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Private key saved")

    print("Generating the certificates")
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Mitmproxy CA"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Mitmproxy Root CA"),
    ])

    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(private_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=3650))  # Valid for 10 years
    cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(private_key, hashes.SHA256(), default_backend())

    cert_path = os.path.join(cert_dir, "ca_cert.pem")
    with open(cert_path, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"CA private key and certificate have been generated in the '{cert_dir}' directory.")
    return cert_path


def transfer_ca_certificate(cert_path, remote_ip, remote_user):
    """
    Transfer the CA certificate to a remote machine using SCP.
    """
    print("Using SCP to copy the certificate to the remote machine")
    scp_command = f"scp {cert_path} {remote_user}@{remote_ip}:/tmp/mitmproxy-ca.crt"
    subprocess.run(scp_command, shell=True, check=True)
    print(f"Transferred CA certificate to {remote_ip}:/tmp/mitmproxy-ca.crt")

def install_ca_certificate_remote(remote_ip, remote_user, remote_password):
    """
    Install the CA certificate on the remote machine using SSH.
    """
    print("Establishing SSH connection to the remote machine")
    ssh = paramiko.SSHClient()
    print("Setting missing host key policy")
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("Connecting ssh")
    ssh.connect(remote_ip, username=remote_user, password=remote_password)

    print("Installing the CA certificate on the remote machine")
    install_command = "sudo cp /tmp/mitmproxy-ca.crt /usr/local/share/ca-certificates/mitmproxy-ca.crt && sudo update-ca-certificates"
    stdin, stdout, stderr = ssh.exec_command(install_command)

    print("Reading output and errors")
    output = stdout.read().decode()
    error = stderr.read().decode()

    if error:
        print(f"Error installing certificate: {error}")
    else:
        print("CA certificate installed successfully.")
    print("SSH connection closed")
    ssh.close()
