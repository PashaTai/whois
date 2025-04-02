from fastapi import FastAPI, HTTPException
import whois
import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import certifi
import uvicorn

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "WHOIS и SSL микросервис работает!"}

@app.get("/whois/{domain}")
def get_whois(domain: str):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "name_servers": w.name_servers,
            "status": w.status
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ошибка при получении WHOIS: {str(e)}")

@app.get("/ssl/{domain}")
def get_ssl(domain: str):
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        cert_bin = conn.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        
        return {
            "domain": domain,
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_until": cert.not_valid_after.isoformat(),
            "serial_number": cert.serial_number,
            "version": cert.version.name
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ошибка при получении SSL: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
