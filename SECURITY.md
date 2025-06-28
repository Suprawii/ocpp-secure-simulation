# Security Configuration for OCPP 2.0.1 CSMS

## TLS / Certificates

- Only TLS 1.2 and above are allowed.
- For TLS 1.2, only the following ciphers are allowed:  
  - ECDHE-ECDSA-AES128-GCM-SHA256  
  - ECDHE-ECDSA-AES256-GCM-SHA384  
  - ECDHE-RSA-AES128-GCM-SHA256  
  - ECDHE-RSA-AES256-GCM-SHA384  
- For TLS 1.3, all standard ciphers are accepted.
- Client certificates are **required** and must be signed by the CA at `certs/ca.crt`.
- Server certificate and key must be in `certs/server.crt` and `certs/server.key`.

## Authentication

- Basic authentication is used.
- Passwords must be at least 12 characters, with at least one uppercase, one lowercase, one digit, and one special character.
- Edit password requirements in `main.py` as needed.

## Security Events

- All security-related events (TLS version, cipher negotiation, authentication, certificate validation) are emitted to the dashboard for audit/logging.

## Updating Certificates

- Replace files in the `certs/` directory.
- Restart the CSMS application after updating certificates.

## Changing Credentials

- Update `self.auth_credentials` in `main.py`.
- Ensure passwords meet the strength requirements.