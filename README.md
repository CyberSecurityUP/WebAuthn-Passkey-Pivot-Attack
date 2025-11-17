## 🚀 WebAuthn Passkey Pivot Attack PoC

This repository contains a Proof of Concept (PoC) for a **WebAuthn Passkey Pivot Attack**. This vulnerability exploits high-privilege browser extensions (specifically those using APIs like `chrome.webAuthenticationProxy` in Chromium-based browsers) to intercept and control WebAuthn operations (`navigator.credentials.create` and `navigator.credentials.get`).

### ⚠️ Disclaimer

This tool is for **educational and defensive security research purposes only**. Do not use this tool on any system or network you do not own or have explicit permission to test. The developers assume no liability for misuse.

### 🎯 Attack Description

<img width="752" height="357" alt="image" src="https://github.com/user-attachments/assets/63ec54db-5aaf-4796-b2f7-9e12e49aed7d" />


The WebAuthn Pivot Attack works in two main phases:

1.  **Registration Pivot (`navigator.credentials.create`):** The extension intercepts the registration request and forges the response. Instead of registering the user's legitimate Passkey (e.g., from a device or platform authenticator), the extension registers a **secret cryptographic key** that it controls (the "Pivot Key"). The PoC uses an ECDSA P-256 key and generates an **Attestation Format "none"** response.
2.  **Authentication Pivot (`navigator.credentials.get`):** During subsequent login attempts, the extension intercepts the authentication request, increments the `signCount`, and uses its stored **private Pivot Key** to generate a valid cryptographic signature for the server's challenge. This grants the attacker unauthorized access.

### ⚙️ PoC Implementation Details

The core logic resides in the `sw.js` (Service Worker) file.

* **API Usage:** It hooks into the WebAuthn API using `chrome.webAuthenticationProxy` listeners:
    * `onCreateRequest` is handled by `pivotCreate()`.
    * `onGetRequest` is handled by `pivotGet()`.
* **Cryptography:** Uses the Web Crypto API to generate and manage the ECDSA P-256 (ES256) key pair and perform signing operations.
* **Data Forgery:** Includes functions to correctly build and serialize WebAuthn data structures, including:
    * CBOR serialization.
    * COSE Key formatting.
    * DER/SPKI serialization for the public key material.
    * Construction of `clientDataJSON` and `authenticatorData`.

### 🛠️ How to Run the PoC

This PoC requires a browser environment that supports the `chrome.webAuthenticationProxy` API (or similar high-privilege access to WebAuthn) and the Manifest V3 Service Worker.

1.  **Load the Extension:**
    * Go to the browser's Extensions management page (`chrome://extensions`).
    * Enable **Developer mode**.
    * Click **"Load unpacked"** and select the directory containing the `sw.js` and other necessary files (manifest, etc., which are assumed to exist).
2.  **Initiate Attack:**
    * Navigate to a target website that supports Passkey/WebAuthn registration.
    * Initiate the **registration** process. The extension will intercept the call and register its own key.
    * Initiate the **login/authentication** process. The extension will intercept and sign the challenge using the newly registered "Pivot Key."

<img width="652" height="367" alt="Captura de Tela 2025-11-17 às 15 23 45" src="https://github.com/user-attachments/assets/54ab688c-12a9-4eb5-b223-b7857e64053d" />

<img width="1050" height="499" alt="Captura de Tela 2025-11-17 às 15 23 31" src="https://github.com/user-attachments/assets/d94b1c1f-09f3-47f7-8be8-a3bce94df469" />

<img width="732" height="450" alt="Captura de Tela 2025-11-17 às 15 22 53" src="https://github.com/user-attachments/assets/9ff0e023-ba77-46bd-94be-ddafd61bdb57" />

### 📝 Key Security Takeaways

This PoC highlights the critical risk posed by malicious browser extensions when relying on **Platform Authenticators** (software-based Passkeys).

**Defensive Measures for Relying Parties (RPs):**

* **Enforce Attestation:** Do not accept the "none" Attestation Format. Require a verifiable attestation format (e.g., "packed," "fido-u2f") and check the Authenticator Attestation GUID (AAGUID) to ensure the authenticator is genuine and not an extension-controlled software key.
* **Promote Hardware Keys:** Encourage users to register **Cross-Platform Authenticators (Hardware Security Keys)**, which are resistant to this type of software key extraction and pivoting.
