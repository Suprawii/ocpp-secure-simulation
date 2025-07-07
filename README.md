# OCPP 2.0.1 Secure Communication Simulation

This project demonstrates a secure implementation of the Open Charge Point Protocol (OCPP) 2.0.1, focusing on the simulation of secure communication between an electric vehicle (EV) charge point and a central system (CSMS). The implementation highlights industry-standard security features such as mutual TLS authentication, certificate management, and secure message exchange.


## Features

- **OCPP 2.0.1 Protocol Simulation**: Communication between a simulated charge point and central system.
- **Mutual TLS Authentication**: Both server and client authenticate each other using certificates signed by a common CA.
- **Automated Certificate Generation**: Script to generate CA, server, and client certificates.
- **Security Profile 2 Compliance**: Emulates the requirements of OCPP Security Profiles.
- **Event Logging**: Security events and message exchanges can be logged for monitoring.



## Getting Started

### 1. Clone the Repository

git clone https://github.com/Suprawii/ocpp-secure-simulation.git

cd ocpp-secure-simulation

### 2. Install Dependencies

pip install -r requirements.txt

### 3. Generate a Fernet Key
Fernet Key Generation (for Secure Password Storage)
Before running the Charge Point or CSMS, you must generate a Fernet encryption key for securing sensitive data such as passwords : 

python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > fernet.key 

### 4. Generate Certificates

python generate_certs.py

This will create the necessary CA, server, and client certificates in the appropriate folders.

### 5. Run the Central System

cd central_system

python main.py

### 6. Run the Charge Point


cd charge_point

python main.py


## Security Notes

- **Certificates**: All TLS certificates are generated locally for simulation using the provided script. In production, use a secure CA and manage private keys carefully.
- **Authentication**: The charge point authenticates to the CSMS using both mutual TLS and HTTP Basic Auth.
- **Fernet Key:** : The Fernet key is used for symmetric encryption (e.g., for passwords). Store it securely and do not share or commit it.
- **Configuration**: Adjust configuration files (e.g., `config.ini`) as needed for your environment.


## References

- [OCPP 2.0.1 Specification](https://www.openchargealliance.org/protocols/ocpp-201/)
- [Python cryptography docs](https://cryptography.io/en/latest/)
- [websockets library](https://websockets.readthedocs.io/en/stable/)
](https://github.com/Suprawii/ocpp-secure-simulation)
