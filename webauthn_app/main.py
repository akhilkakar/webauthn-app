#!/usr/bin/env python3
"""
WebAuthn Backend Server using FastAPI
Install dependencies: pip install fastapi uvicorn webauthn
Run with: uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import base64
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import secrets
import os

app = FastAPI(title="WebAuthn API", version="1.0.0")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Next.js default ports
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (use proper database in production)
users_db: Dict[str, Dict] = {}
challenges_db: Dict[str, str] = {}

# WebAuthn configuration
RP_ID = "localhost"  # Your domain in production
RP_NAME = "WebAuthn Demo"
RP_ORIGIN = "http://localhost:3000"  # Your frontend URL

# Request/Response models
class RegisterBeginRequest(BaseModel):
    username: str

class RegisterCompleteRequest(BaseModel):
    username: str
    credential: Dict[str, Any]
    challenge: str

class AuthenticateBeginRequest(BaseModel):
    username: str

class AuthenticateCompleteRequest(BaseModel):
    username: str
    assertion: Dict[str, Any]
    challenge: str

def base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes"""
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    
    # Replace URL-safe characters
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)

def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string"""
    encoded = base64.b64encode(data).decode('ascii')
    return encoded.replace('+', '-').replace('/', '_').replace('=', '')

@app.get("/")
async def root():
    return {"message": "WebAuthn API Server", "users": len(users_db)}

@app.post("/register/begin")
async def register_begin(request: RegisterBeginRequest):
    """Begin WebAuthn registration process"""
    try:
        username = request.username
        
        # Check if user already exists
        if username in users_db:
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Generate user ID
        user_id = secrets.token_bytes(32)
        
        # Generate registration options
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,
            user_name=username,
            user_display_name=username,
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(        #Crypto algorithms we accept
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            timeout=60000, #60 seconds to complete
        )
        
        # Store challenge for verification
        challenge_key = f"reg_{username}_{options.challenge}"
        challenges_db[challenge_key] = {
            "challenge": options.challenge,
            "user_id": base64url_encode(user_id),
            "username": username,
            "type": "registration"
        }
        
        # Convert to JSON-serializable format
        response = {
            "publicKey": {
                "rp": {"id": options.rp.id, "name": options.rp.name},
                "user": {
                    "id": base64url_encode(user_id),
                    "name": options.user.name,
                    "displayName": options.user.display_name,
                },
                "challenge": options.challenge,
                "pubKeyCredParams": [
                    {"alg": alg.alg, "type": "public-key"} 
                    for alg in options.pub_key_cred_params
                ],
                "timeout": options.timeout,
                "attestation": options.attestation,
                "authenticatorSelection": {
                    "userVerification": options.authenticator_selection.user_verification.value
                }
            }
        }
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration setup failed: {str(e)}")

@app.post("/register/complete")
async def register_complete(request: RegisterCompleteRequest):
    """Complete WebAuthn registration process"""
    try:
        username = request.username
        credential_data = request.credential
        
        # Find the challenge
        challenge_key = f"reg_{username}_{request.challenge}"
        if challenge_key not in challenges_db:
            raise HTTPException(status_code=400, detail="Invalid challenge")
        
        challenge_info = challenges_db[challenge_key]
        
        # Create RegistrationCredential object
        credential = RegistrationCredential(
            id=credential_data["id"],
            raw_id=base64url_decode(credential_data["rawId"]),
            response={
                "client_data_json": base64url_decode(credential_data["response"]["clientDataJSON"]),
                "attestation_object": base64url_decode(credential_data["response"]["attestationObject"]),
            },
            type=credential_data["type"],
        )
        
        # Verify the registration
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_decode(challenge_info["challenge"]),
            expected_origin=RP_ORIGIN,
            expected_rp_id=RP_ID,
        )
        
        if not verification.verified:
            raise HTTPException(status_code=400, detail="Registration verification failed")
        
        # Store user credentials
        users_db[username] = {
            "id": challenge_info["user_id"],
            "username": username,
            "credentials": [{
                "id": credential.id,
                "public_key": base64url_encode(verification.credential_public_key),
                "sign_count": verification.sign_count,
            }]
        }
        
        # Clean up challenge
        del challenges_db[challenge_key]
        
        return {"verified": True, "message": "Registration successful"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration verification failed: {str(e)}")

@app.post("/authenticate/begin")
async def authenticate_begin(request: AuthenticateBeginRequest):
    """Begin WebAuthn authentication process"""
    try:
        username = request.username
        
        # Check if user exists
        if username not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        user_info = users_db[username]
        
        # Get user's credentials
        allowed_credentials = []
        for cred in user_info["credentials"]:
            allowed_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_decode(base64url_encode(cred["id"].encode()) if isinstance(cred["id"], str) else cred["id"]),
                    type="public-key",
                    transports=[AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE, AuthenticatorTransport.INTERNAL],
                )
            )
        
        # Generate authentication options
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=allowed_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
            timeout=60000,
        )
        
        # Store challenge for verification
        challenge_key = f"auth_{username}_{options.challenge}"
        challenges_db[challenge_key] = {
            "challenge": options.challenge,
            "username": username,
            "type": "authentication"
        }
        
        # Convert to JSON-serializable format
        response = {
            "publicKey": {
                "challenge": options.challenge,
                "timeout": options.timeout,
                "rpId": options.rp_id,
                "allowCredentials": [
                    {
                        "id": base64url_encode(cred.id),
                        "type": cred.type,
                        "transports": [t.value for t in cred.transports] if cred.transports else []
                    }
                    for cred in options.allow_credentials
                ],
                "userVerification": options.user_verification.value,
            }
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication setup failed: {str(e)}")

@app.post("/authenticate/complete")
async def authenticate_complete(request: AuthenticateCompleteRequest):
    """Complete WebAuthn authentication process"""
    try:
        username = request.username
        assertion_data = request.assertion
        
        # Check if user exists
        if username not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Find the challenge
        challenge_key = f"auth_{username}_{request.challenge}"
        if challenge_key not in challenges_db:
            raise HTTPException(status_code=400, detail="Invalid challenge")
        
        challenge_info = challenges_db[challenge_key]
        user_info = users_db[username]
        
        # Find the credential used
        credential_id = assertion_data["id"]
        user_credential = None
        for cred in user_info["credentials"]:
            if cred["id"] == credential_id:
                user_credential = cred
                break
        
        if not user_credential:
            raise HTTPException(status_code=400, detail="Credential not found")
        
        # Create AuthenticationCredential object
        credential = AuthenticationCredential(
            id=assertion_data["id"],
            raw_id=base64url_decode(assertion_data["rawId"]),
            response={
                "client_data_json": base64url_decode(assertion_data["response"]["clientDataJSON"]),
                "authenticator_data": base64url_decode(assertion_data["response"]["authenticatorData"]),
                "signature": base64url_decode(assertion_data["response"]["signature"]),
                "user_handle": base64url_decode(assertion_data["response"]["userHandle"]) if assertion_data["response"]["userHandle"] else None,
            },
            type=assertion_data["type"],
        )
        
        # Verify the authentication
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_decode(challenge_info["challenge"]),
            expected_origin=RP_ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64url_decode(user_credential["public_key"]),
            credential_current_sign_count=user_credential["sign_count"],
        )
        
        if not verification.verified:
            raise HTTPException(status_code=400, detail="Authentication verification failed")
        
        # Update sign count
        user_credential["sign_count"] = verification.new_sign_count
        
        # Clean up challenge
        del challenges_db[challenge_key]
        
        return {"verified": True, "message": "Authentication successful", "user": username}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication verification failed: {str(e)}")

@app.get("/users")
async def list_users():
    """List all registered users (for debugging)"""
    return {
        "users": list(users_db.keys()),
        "total": len(users_db)
    }

@app.delete("/users/{username}")
async def delete_user(username: str):
    """Delete a user (for debugging)"""
    if username in users_db:
        del users_db[username]
        return {"message": f"User {username} deleted"}
    raise HTTPException(status_code=404, detail="User not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)