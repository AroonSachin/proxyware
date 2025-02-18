
import argparse
from utils.certificategenerator.certificatinator import install_ca_certificate_remote,generate_ca_certificate,transfer_ca_certificate
from pathlib import Path
from proxyware.calls import InterceptEditProxy

# class InterceptEditProxy:
#     def __init__(self):
#         pass

def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="A tool to intercept, edit, and send HTTP/S requests and responses.")
    
    parser.add_argument(
        "--host", 
        action='store', 
        default="127.0.0.1", 
        required=True, 
        help="The host IP address to listen on. Default is 127.0.0.1 (localhost)."
    )
    
    parser.add_argument(
        "--port", 
        action='store', 
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
    print(f"Certicate path : {cert_path}")
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
        transfer_ca_certificate(cert_path, remote_ip, remote_user)

        # 4. Install the CA certificate on the remote machine
        print(f"Installin CA certificate in the machine - IP: '{remote_ip}', User: '{remote_user}'")
        install_ca_certificate_remote(remote_ip, remote_user, remote_password)

    # Initialize the proxy server with the InterceptEditProxy addon
    print("Addons added to MITM")
    addons = [InterceptEditProxy()]
    
    # Show stored HTTP calls (optional)
    InterceptEditProxy().show_stored_calls()
    # show_stored_calls()
    # Start mitmproxy with the script
    from mitmproxy.tools.main import mitmproxy
    mitmproxy(["-s","src/proxyware/main.py", '--listen-host',host,"--listen-port",str(port),"--mode","transparent"])

if __name__ == "__main__":
    main()
