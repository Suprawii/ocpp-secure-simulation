# OCPP 2.0.1 Secure Communication Simulation

This project demonstrates a secure implementation of the Open Charge Point Protocol (OCPP) 2.0.1, focusing on the simulation of secure communication between an electric vehicle (EV) charge point and a central system (CSMS). The implementation highlights industry-standard security features such as mutual TLS authentication, certificate management, and secure message exchange.

## 🔐 Features

- **OCPP 2.0.1 Protocol Simulation** – Communication between a simulated charge point and central system.  
- **Mutual TLS Authentication** – Both server and client authenticate with certificates signed by a common CA.  
- **Automated Certificate Generation** – Script to generate CA, server, and client certificates.  
- **Security Profile 2 Compliance** – Emulates the requirements of OCPP Security Profiles.  
- **Replay Attack Protection** – Messages are secured with nonces to prevent reuse by attackers.  
- **DoS Rate Limiting** – Controls excessive or malicious requests to protect the CSMS.  
- **Event Logging & Monitoring** – Real-time logging of security events and message exchanges.  
- **Secure Message Exchange** – All messages are encrypted and signed to ensure authenticity and integrity.

## Getting Started

### 1. Clone the Repository

```sh
git clone https://github.com/Suprawii/ocpp-secure-simulation.git
cd ocpp-secure-simulation
```

### 2. Install Dependencies

```sh
pip install -r requirements.txt
```

### 3. Generate Certificates

```sh
python generate_certs.py
```
This will create the necessary CA, server, and client certificates in the appropriate folders.

### 4. Generate a Fernet key

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Then, set the environment variable for the charge point encryption key:

**On Windows (PowerShell):**
```sh
$env:CP_FERNET_KEY = "PASTE_THE_KEY_HERE"
```
**On Linux/macOS:**
```sh
export CP_FERNET_KEY="PASTE_THE_KEY_HERE"
```

### 5. Run the Central System 

```sh
cd central_system
python main.py
```

### 6. Run the Charge Point

```sh
cd ../charge_point
python main.py
```

## Security Notes

- **Certificates**: All TLS certificates are generated locally for simulation using the provided script. In production, always use a trusted CA and protect private keys with strict access controls.
- **Authentication**: The charge point authenticates to the CSMS using both mutual TLS and HTTP Basic Auth. Charge point credentials (passwords) are generated dynamically, encrypted locally with Fernet (using the key in `CP_FERNET_KEY`), and never stored in plaintext.
- **Credential Storage**: Charge point passwords are encrypted with Fernet on the client. On the CSMS, they are stored as bcrypt hashes in an encrypted SQLite database.
- **Replay & DoS Protection**: The system uses nonces and strict message timing to prevent replay attacks, and implements server-side rate limiting to defend against DoS attempts.
- **Configuration**: Adjust configuration files (e.g., `config.ini`) as needed for your environment, including endpoint URLs, cert paths, and security parameters.
- **Environment Variables**: Never commit your Fernet key or other sensitive secrets to version control. Always set them securely via environment variables.

## References

- [OCPP 2.0.1 Specification](https://www.openchargealliance.org/protocols/ocpp-201/)
- [Python cryptography docs](https://cryptography.io/en/latest/)
- [websockets library](https://websockets.readthedocs.io/en/stable/)