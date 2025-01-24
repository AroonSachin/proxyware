import mitmproxy.http
from mitmproxy import ctx
import logging
import json
import argparse
import os
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
import paramiko

# List to store intercepted requests and responses
intercepted_calls = []

class InterceptEditProxy:
    def __init__(self):
        pass

    def request(self, flow: mitmproxy.http.HTTPFlow):
        """
        Intercept HTTP request, store it, and allow editing.
        """
        logger.info(f"Intercepted request: {flow.request.method} {flow.request.url}")

        # Store the request data
        request_data = {
            "method": flow.request.method,
            "url": flow.request.url,
            "headers": dict(flow.request.headers),
            "body": flow.request.get_text()
        }

        intercepted_calls.append({"request": request_data, "response": None})

        # Example: Modify the request (if needed)
        # flow.request.headers["User-Agent"] = "Modified User-Agent"
        pass

    def response(self, flow: mitmproxy.http.HTTPFlow):
        """
        Intercept HTTP response, store it, allow editing, and send the modified response back.
        """
        logger.info(f"Intercepted response: {flow.request.method} {flow.request.url}")

        print("Finding the corresponding intercepted request to store the response")
        for call in reversed(intercepted_calls):
            if call["request"]["url"] == flow.request.url:
                call["response"] = {
                    "status_code": flow.response.status_code,
                    "headers": dict(flow.response.headers),
                    "body": flow.response.get_text()
                }
                break

        # Store and modify the response if needed
        # For now, the response is stored and you can modify it via editing prompt.
        # Allow user to edit response content interactively or with CLI commands
        self.edit_response(call["response"])

        # Modify the response body (optional)
        flow.response.content = call["response"]["body"].encode('utf-8')

    def edit_response(self, response_data):
        """
        Allow the user to edit the response body and headers.
        """
        print("\nResponse Editing:")
        print("1. Edit Body")
        print("2. Edit Headers")
        print("3. Send Response as is")
        
        choice = input("Choose an option (1-3): ").strip()

        if choice == '1':
            # Edit the body of the response
            new_body = input("Enter new response body: ")
            response_data["body"] = new_body
        elif choice == '2':
            # Edit headers
            new_headers = input("Enter new headers (key:value), separated by commas: ").strip()
            headers = dict(item.split(":") for item in new_headers.split(","))
            response_data["headers"] = headers
        elif choice == '3':
            # Send the response as-is
            print("Sending the response without changes.")
        else:
            print("Invalid choice. Sending the response without changes.")

    @staticmethod
    def show_stored_calls():
        """
        Display stored requests and responses.
        """
        print("\nStored HTTP Calls:")
        for i, call in enumerate(intercepted_calls):
            print(f"{i+1}. Request URL: {call['request']['url']}")
            if call['response']:
                print(f"   Response Status: {call['response']['status_code']}")
                print(f"   Response Body (truncated): {call['response']['body'][:100]}")
            else:
                print("   Response: Not yet received.")

def generate_ca_certificate(cert_dir="mitmproxy-ca"):
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


def transfer_ca_certificate(cert_path, remote_ip, remote_user, remote_password):
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
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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

def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="A tool to intercept, edit, and send HTTP/S requests and responses.")
    
    parser.add_argument(
        "--host", 
        type=str, 
        default="127.0.0.1", 
        required=True, 
        help="The host IP address to listen on. Default is 127.0.0.1 (localhost)."
    )
    
    parser.add_argument(
        "--port", 
        type=int, 
        default=8080, 
        required=True, 
        help="The port to listen on. Default is 8080."
    )
    
    parser.add_argument(
        "--target_ip", 
        type=str, 
        required=False, 
        help="The IP address of the remote server."
    )
    
    parser.add_argument(
        "--target_user", 
        type=str, 
        required=False, 
        help="The username for the remote server."
    )
    
    parser.add_argument(
        "--target_password", 
        type=str, 
        required=False, 
        help="The password for the remote server."
    )
    
    # Parse arguments
    return parser.parse_args()


def main():
    """
    The main entry point for the proxy server.
    """

    # Generate CA certificate
    cert_path = generate_ca_certificate()

    # Parse the command-line arguments
    args = parse_args()
    
    host = args.host
    port = args.port
    remote_ip = args.target_ip
    remote_user = args.target_user
    remote_password = args.target_password

    if remote_ip != "" and remote_ip is not None:
        print(f"Connecting to remote server {remote_ip} with user {remote_user}...")
        # 3. Transfer CA certificate to the remote machine
        print("Transfering CA certificate")
        transfer_ca_certificate(cert_path, remote_ip, remote_user, remote_password)

        # 4. Install the CA certificate on the remote machine
        print(f"Installin CA certificate in the machine - IP: '{remote_ip}', User: '{remote_user}'")
        install_ca_certificate_remote(remote_ip, remote_user, remote_password)

    # Initialize the proxy server with the InterceptEditProxy addon
    addons = [InterceptEditProxy()]
    
    # Show stored HTTP calls (optional)
    InterceptEditProxy().show_stored_calls()

    # Start mitmproxy with the script
    from mitmproxy.tools.main import mitmproxy
    mitmproxy(["-s", "src/http_interceptor.py", '--listen-host',host,"--listen-port", str(port)])

if __name__ == "__main__":
    main()
