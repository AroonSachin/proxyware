import mitmproxy.http
from mitmproxy import ctx
import logging
import json
import argparse

# Setup logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# List to store intercepted requests and responses
intercepted_calls = []

#Get arguments from the user
parser = argparse.ArgumentParser('-host',description='To scan on a specific host')

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

        # Find the corresponding intercepted request to store the response
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

def main():
    """
    The main entry point for the proxy server.
    """
    # Initialize the proxy server with the InterceptEditProxy addon
    addons = [InterceptEditProxy()]
    
    # Show stored HTTP calls (optional)
    InterceptEditProxy().show_stored_calls()

    # Start mitmproxy with the script
    from mitmproxy.tools.main import mitmproxy
    mitmproxy(["-s", "src/http_interceptor.py", "--listen-port", "8080"])

if __name__ == "__main__":
    # Execute the main function
    main()
