# MMG AUTO - MMG Checkout URL Generator & Callback Handler

This project provides a simple Flask web server that:
1.  Generates an MMG Checkout URL using parameters from `setup.cfg` and the merchant's public key.
2.  Opens the generated URL in the default web browser.
3.  Uses ngrok to expose a public endpoint (`/payment/callback`).
4.  Listens for the MMG Checkout callback request on the ngrok endpoint.
5.  Automatically decrypts the `token` parameter from the callback URL using the merchant's private key and prints the result.

## Purpose

To automate the process of generating an MMG checkout URL, initiating the checkout flow in a browser, and then receiving and decrypting the subsequent callback token. This facilitates end-to-end testing of the MMG checkout integration.

## Prerequisites

*   Python 3.x
*   pip (Python package installer)
*   ngrok account and executable (if not using `pyngrok`'s managed version, ensure it's in your PATH). You may need to authenticate ngrok with your authtoken (`ngrok authtoken <YOUR_AUTH_TOKEN>`).

## Project Structure & Dependencies

This script assumes the following directory structure *within* the `MMG AUTO` folder:

```
MMG AUTO/
├── app.py          # This script
├── requirements.txt
├── README.md       # This file
├── keys/
│   ├── {merchant_msisdn}.private.pem  # Your private key file
│   └── {merchant_msisdn}.public.pem   # Your public key file (needed for request encryption)
└── setup.cfg           # Configuration file
```

*   **`setup.cfg`**: Must exist in the `MMG AUTO` directory and contain a `[DEFAULT]` section with necessary keys like `merchant_msisdn`, `secret_key`, `amount`, `clientId`, and optionally `merchant`.
*   **`keys/{merchant_msisdn}.private.pem`**: The RSA private key for decrypting the callback, located within the `keys` sub-folder.
*   **`keys/{merchant_msisdn}.public.pem`**: The RSA public key for encrypting the initial checkout request token, located within the `keys` sub-folder.

## Setup

1.  **Navigate to the project directory:**
    ```bash
    cd /Users/user/Downloads/MMG/MMG\ AUTO
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Running the Application

1.  **Ensure prerequisites and dependencies are met.** Make sure `setup.cfg` and both the private and public key files in the local `keys/` sub-folder are present and correctly configured within the `MMG AUTO` directory.

2.  **Run the application (from within the `MMG AUTO` directory):**
    ```bash
    python app.py
    ```

3.  **Observe the output & workflow:**
    *   The script will load the merchant keys and configuration.
    *   It will generate the checkout request token, encrypt it, and construct the full checkout URL, printing details to the console.
    *   It will attempt to open the generated checkout URL in your default web browser.
    *   It will start an ngrok tunnel and print the public URL (e.g., `https://<random_string>.ngrok.io`).
    *   It will print the specific callback URL (e.g., `https://<random_string>.ngrok.io/payment/callback`) that MMG should be configured to use.
    *   The Flask server will start listening locally on port 5000, waiting for the callback via the ngrok tunnel.

4.  **Complete Checkout:** Follow the checkout process in the browser window that was opened.

5.  **Check Console:** After completing the checkout, MMG should send a request to the callback URL. The Flask server will receive this, decrypt the token, and print the decrypted JSON data to the console where `app.py` is running.

6.  **Stop the application:** Press `Ctrl+C` in the terminal. This will stop the Flask server and disconnect the ngrok tunnel.

## Integration into Other Projects

The core logic can be adapted for use in other Python projects:

*   **Request Encryption:** Use the `encrypt_request` function (requires `cryptography` and the merchant's public key).
*   **URL Generation:** Adapt the `generate_checkout_url` function (requires `encrypt_request`, config parameters, and potentially `base64`, `time`).
*   **Callback Decryption:** Use the `decrypt_token` function (requires `cryptography`, `base64`, `json`, and the merchant's private key).

Remember to handle key loading and configuration appropriately within your target project.
