import os
import base64
import json
import configparser
import time
import webbrowser
from flask import Flask, request
from pyngrok import ngrok
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# --- Configuration ---
config = configparser.ConfigParser()
# Construct the path to setup.cfg relative to this script's directory
# Use '.' for current directory instead of '..' for parent
config_path = os.path.join(os.path.dirname(__file__), '.', 'setup.cfg')
config.read(config_path)

try:
    # Read all required config values within the main try block
    merchant_msisdn = config['DEFAULT']['merchant_msisdn']
    merchant = config['DEFAULT'].get('merchant', 'DefaultMerchantName') # Use .get for optional with default
    secret_key = config['DEFAULT']['secret_key']
    amount = config['DEFAULT']['amount']
    clientId = config['DEFAULT']['clientId']
    # Assuming description is fixed or add to config if needed
    description = "MMG Auto Product"
except KeyError as e:
    # Handle specific missing keys
    print(f"Error: Missing required key '{e}' in {config_path}")
    exit(1)
except Exception as e:
    # Handle other potential errors during config reading
    print(f"Error reading config file {config_path}: {e}")
    exit(1)

# --- Load Merchant Keys ---
private_key = None
public_key = None
# Use '.' for current directory instead of '..' for parent
priv_key_path = os.path.join(os.path.dirname(__file__), '.', 'keys', f'{merchant_msisdn}.private.pem')
pub_key_path = os.path.join(os.path.dirname(__file__), '.', 'keys', f'{merchant_msisdn}.public.pem')

# Load Private Key
try:
    with open(priv_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend())
    print(f"Private key loaded successfully from: {priv_key_path}")
except FileNotFoundError:
    print(f"Error: Private key file not found at {priv_key_path}")
    exit(1)
except Exception as e:
    print(f"Error loading private key: {e}")
    exit(1)

# Load Public Key (for encrypting request based on demo script)
try:
    with open(pub_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    print(f"Public key loaded successfully from: {pub_key_path}")
except FileNotFoundError:
    print(f"Error: Public key file not found at {pub_key_path}")
    # Allow continuing if only decryption is needed, but URL generation will fail
    print("Warning: URL generation will fail without the public key.")
except Exception as e:
    print(f"Error loading public key: {e}")
    exit(1)


# --- Encryption Function (for Request) ---
def encrypt_request(checkout_object):
    """
    Encrypt the checkout object using RSA encryption (using Merchant Public Key based on demo).
    """
    if not public_key:
        raise ValueError("Public key not loaded. Cannot encrypt request.")

    json_object = json.dumps(checkout_object, indent=4)
    print(f"\n--- Checkout Request Object ---\n{json_object}\n")

    # message to bytes
    json_bytes = json_object.encode("ISO-8859-1") # Match demo encoding

    # encrypt message
    ciphertext = public_key.encrypt(
        json_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return ciphertext

# --- Decryption Function (for Callback) ---
def decrypt_token(encrypted_token):
    """
    Decrypts the MMG response token using the merchant's private key.
    """
    if not private_key:
        return {"error": "Private key not loaded."}

    try:
        # Debug print to see raw token
        print(f"Raw token length: {len(encrypted_token)}")
        
        # Handle URL encoding in the token
        encrypted_token = encrypted_token.replace('-', '+').replace('_', '/')
        
        # Pad if necessary (handle potential base64 padding issues)
        padding_needed = 4 - (len(encrypted_token) % 4)
        if padding_needed < 4:  # Only pad if needed
            encrypted_token += '=' * padding_needed
            
        print(f"Processed token length: {len(encrypted_token)}")
        
        # Base64 decode
        try:
            ciphertext = base64.b64decode(encrypted_token)
        except Exception as e:
            print(f"Standard base64 decode failed: {e}, trying urlsafe...")
            ciphertext = base64.urlsafe_b64decode(encrypted_token)
        
        print(f"Decoded ciphertext length: {len(ciphertext)}")

        # Decrypt using RSA-OAEP with SHA256
        decrypted_data = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None)
        )

        # Decode bytes to string
        try:
            decrypted_string = decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            # Fall back to ISO-8859-1 if UTF-8 fails
            decrypted_string = decrypted_data.decode('ISO-8859-1')

        print(f"Decrypted string: {decrypted_string}")
        
        # Parse JSON
        decrypted_json = json.loads(decrypted_string)
        return decrypted_json
    except Exception as e:
        print(f"Decryption error details: {str(e)}")
        return {"error": "Decryption failed.", "details": str(e)}

# --- Result Code Mapping ---
RESULT_CODES = {
    "0": "Transaction Successful",
    "1": "Agent Not Registered",
    "2": "Payment Failed",
    "3": "Invalid Secret Key",
    "4": "Merchant ID Mismatch",
    "5": "Token Decryption Failed",
    "6": "Transaction Cancelled by User",
    "7": "Request Timed Out"
}

# --- Flask App ---
app = Flask(__name__)

@app.route('/payment/callback', methods=['GET', 'POST'])
def payment_callback():
    """
    Handles the callback from MMG, decrypts the token, and prints the result.
    """
    print("\n--- Callback Received ---")
    
    # Get token from either query parameters (GET) or form data (POST)
    if request.method == 'POST':
        token = request.form.get('token') or request.args.get('token')
    else:
        token = request.args.get('token')

    if not token:
        print("Error: 'token' parameter missing in the request.")
        return "Error: Missing token parameter", 400

    print(f"Received Encrypted Token (first 50 chars): {token[:50]}...")

    decrypted_data = decrypt_token(token)

    print("\n--- Parsed Callback Data ---")
    if isinstance(decrypted_data, dict) and "error" not in decrypted_data:
        # Extract fields safely using .get()
        merchant_tx_id = decrypted_data.get("merchantTransactionId", "N/A")
        mmg_tx_id = decrypted_data.get("transactionId", "N/A")
        result_code = str(decrypted_data.get("resultCode", decrypted_data.get("ResultCode", "N/A"))) # Ensure string for lookup
        result_message = decrypted_data.get("resultMessage", decrypted_data.get("ResultMessage", "N/A"))
        html_response = decrypted_data.get("htmlResponse", "N/A")

        # Get description for the result code
        result_description = RESULT_CODES.get(result_code, "Unknown Result Code")

        print(f"Merchant Transaction ID: {merchant_tx_id}")
        print(f"MMG Transaction ID     : {mmg_tx_id}")
        print(f"Result Code            : {result_code}")
        print(f"Result Message         : {result_message}")
        print(f"Result Description     : {result_description}")
        # Optionally print HTML response if needed, maybe truncated
        # print(f"HTML Response          : {html_response[:100]}...")

    elif isinstance(decrypted_data, dict) and "error" in decrypted_data:
        print(f"Decryption Error: {decrypted_data.get('error')}")
        if decrypted_data.get('details'):
            print(f"Details: {decrypted_data.get('details')}")
    else:
        # Fallback if decryption returns unexpected format
        print("Could not parse decrypted data or decryption failed.")
        print(f"Raw Decrypted Data: {decrypted_data}")

    print("--------------------------\n")

    return "Callback received and processed.", 200

# --- URL Generation ---
def generate_checkout_url(merchant_msisdn, amount, secretKey, description, merchantName, clientId):
    """
    Generates the MMG checkout URL.
    """
    if not public_key:
        print("Error: Cannot generate URL without merchant public key.")
        return None

    timestamp = int(time.time())
    merchant_transaction_id = str(timestamp)

    # Create token parameters according to MMG specifications
    tokenParams = {
        "secretKey": secretKey,
        "amount": amount,
        "merchantId": merchant_msisdn,
        "merchantTransactionId": merchant_transaction_id,
        "productDescription": description,
        "requestInitiationTime": timestamp,
        "merchantName": merchantName
    }

    try:
        encrypted_token_bytes = encrypt_request(tokenParams)
        # URL-safe Base64 encode the encrypted bytes
        encoded_token = base64.urlsafe_b64encode(encrypted_token_bytes).decode('utf-8')

        print("-- CHECKOUT URL PARAMS --")
        print(f"MSISDN: {merchant_msisdn}")
        print(f"CLIENTID: {clientId}")
        print(f"TOKEN (encoded): {encoded_token[:50]}...\n")

        # Construct the URL (using the UAT endpoint from demo)
        checkout_base_url = "https://gtt-uat-checkout.qpass.com:8743/checkout-endpoint/home"
        full_url = f"{checkout_base_url}?token={encoded_token}&merchantId={merchant_msisdn}&X-Client-ID={clientId}"

        print("-- FULL CHECKOUT URL --")
        print(full_url)
        return full_url

    except Exception as e:
        print(f"Error during URL generation: {e}")
        return None


# --- Main Execution ---
if __name__ == '__main__':
    ngrok_tunnel = None # Keep track of the tunnel object
    try:
        # 1. Generate Checkout URL
        print("\n=== Generating MMG Checkout URL ===")
        checkout_url = generate_checkout_url(
            merchant_msisdn, amount, secret_key, description, merchant, clientId
        )

        if not checkout_url:
            print("Failed to generate checkout URL. Exiting.")
            exit(1)

        # 2. Open URL in Browser
        print("\n=== Opening URL in Browser ===")
        try:
            webbrowser.open(checkout_url)
            print("Successfully requested to open URL in default browser.")
        except Exception as e:
            print(f"Could not open browser automatically: {e}")
            print("Please copy and paste the URL above into your browser manually.")

        # 3. Start ngrok tunnel
        print("\n=== Starting Ngrok and Flask Server ===")
        # Use the stable domain instead of generating a random URL
        ngrok_tunnel = ngrok.connect(5000, domain="example.ngrok.freeapp")
        public_url = ngrok_tunnel.public_url
        print(f"\n * Ngrok tunnel established at: {public_url}")
        print(f" * Callback URL for MMG: {public_url}/payment/callback")
        print(" * Waiting for callback...")

        # 4. Start Flask server
        print("\n * Starting Flask server (listening for callback)...")
        app.run(port=5000)

    except Exception as e:
        print(f"Error starting ngrok or Flask: {e}")
        print("Please ensure ngrok is installed and configured correctly.")
        print("You might need to run 'ngrok authtoken <YOUR_AUTH_TOKEN>'")
    finally:
        # Disconnect ngrok when the app stops
        if ngrok_tunnel:
            ngrok.disconnect(ngrok_tunnel.public_url)
            print(" * Ngrok tunnel disconnected.")
        else:
            # If tunnel wasn't started, try to kill any ngrok process (best effort)
            ngrok.kill()
            print(" * Attempted to kill ngrok processes.")
