from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import base64
from typing import Dict, List, Optional
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

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
RP_ID = "localhost"
RP_NAME = "WebAuthn Demo"
RP_ORIGIN = "http://localhost:3000"

# In-memory storage (use proper database in production)
users: Dict[str, Dict] = {}
user_credentials: Dict[str, List[Dict]] = {}
challenges: Dict[str, bytes] = {}  # Store challenge as bytes

# Helper functions
def bytes_to_base64url(data: bytes) -> str:
    """Convert bytes to base64url string (no padding)"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def base64url_to_bytes(data: str) -> bytes:
    """Convert base64url string to bytes (add padding if needed)"""
    # Add padding if necessary
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

# Pydantic models
class RegisterBeginRequest(BaseModel):
    username: str

class RegisterCompleteRequest(BaseModel):
    username: str
    credential: dict

class AuthenticateBeginRequest(BaseModel):
    username: str

class AuthenticateCompleteRequest(BaseModel):
    username: str
    credential: dict

@app.get("/")
async def root():
    return {"message": "WebAuthn Backend Server"}


'''
This endpoint starts the WebAuthn registration process.
It:
1. Validates the username.
2. Creates a unique WebAuthn user identity.
3. Builds registration options for the frontend to pass to navigator.credentials.create().
4. Stores the challenge for later verification.
5. Returns the options to the frontend.

This corresponds to Step 1 (Registration Begin) in the WebAuthn flow.
'''
@app.post("/register/begin")
async def register_begin(request: RegisterBeginRequest):
    username = request.username.strip()
    
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    
    try:
        print(f"Starting registration for user: {username}")
        
        # Generate user ID as string for webauthn 1.11.1 compatibility
        user_id_bytes = secrets.token_bytes(32)
        user_id_string = bytes_to_base64url(user_id_bytes)
        
        # Store user info
        users[username] = {
            "id": user_id_string,
            "username": username,
            "display_name": username
        }
        
        print(f"Generated user ID: {user_id_string}")
        
        # Get existing credentials for this user (for excludeCredentials)
        existing_credentials = []
        if username in user_credentials:
            for cred in user_credentials[username]:
                existing_credentials.append(
                    PublicKeyCredentialDescriptor(
                        id=base64url_to_bytes(cred["credential_id"]),
                        transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE]
                    )
                )
        
        print(f"Found {len(existing_credentials)} existing credentials")
        
        # Generate registration options - compatible with webauthn 1.11.1
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id_string,  # Pass as string, not bytes
            user_name=username,
            user_display_name=username,
            exclude_credentials=existing_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
        
        print("Successfully generated registration options")
        print(f"Options challenge type: {type(options.challenge)}")
        print(f"Options challenge length: {len(options.challenge) if hasattr(options.challenge, '__len__') else 'N/A'}")
        
        # Convert challenge to base64url string for storage and response
        if isinstance(options.challenge, bytes):
            challenge_b64 = bytes_to_base64url(options.challenge)
            print(f"Converted bytes challenge to base64url: {challenge_b64[:20]}...")
        elif isinstance(options.challenge, str):
            challenge_b64 = options.challenge
            print(f"Using string challenge: {challenge_b64[:20]}...")
        else:
            print(f"Unexpected challenge type: {type(options.challenge)}")
            challenge_b64 = str(options.challenge)
        
        # Store challenge using base64url string as key
        challenge_key = f"reg_{username}_{challenge_b64[:16]}"  # Use first 16 chars of challenge as identifier
        challenges[challenge_key] = options.challenge  # Store the original challenge
        
        print(f"Stored challenge with key: {challenge_key}")
        print(f"Challenge B64 for response: {challenge_b64}")
        
        # Prepare response
        response_data = {
            "challenge": challenge_b64,
            "rp": {
                "id": options.rp.id,
                "name": options.rp.name
            },
            "user": {
                "id": bytes_to_base64url(options.user.id),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [
                {"alg": param.alg, "type": param.type}
                for param in options.pub_key_cred_params
            ],
            "timeout": options.timeout,
            "excludeCredentials": [
                {
                    "id": bytes_to_base64url(cred.id),
                    "type": cred.type,
                    "transports": cred.transports
                }
                for cred in options.exclude_credentials
            ] if options.exclude_credentials else [],
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification if options.authenticator_selection else "preferred"
            }
        }
        
        print(f"Returning registration options for {username}")
        return response_data
        
    except Exception as e:
        print(f"Registration begin error: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        traceback.print_exc()
        error_response = {"error": f"Registration failed: {str(e)}"}
        print(f"Sending error response: {error_response}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

'''
Completes the WebAuthn registration process.
It:
1. Receives credential data from frontend (attestation).
2. Retrieves and validates stored challenge.
3. Verifies attestation response using webauthn library.
4. Stores credential information (credential ID, public key, etc.) under the user.
5. Returns success/failure to frontend.
'''
@app.post("/register/complete")
async def register_complete(request: RegisterCompleteRequest):
    username = request.username.strip()
    credential_data = request.credential
    
    try:
        print(f"Completing registration for user: {username}")
        print(f"Received credential data keys: {credential_data.keys()}")
        
        if username not in users:
            raise HTTPException(status_code=400, detail="User not found. Please start registration again.")
        
        user_info = users[username]
        
        # Find the stored challenge
        # Extract challenge from credential response to match with stored challenges
        response_challenge = credential_data.get('response', {}).get('clientDataJSON', '')
        
        challenge_key = None
        stored_challenge = None
        
        # Try to find matching challenge
        for key, challenge_bytes in challenges.items():
            if key.startswith(f"reg_{username}_"):
                challenge_b64 = bytes_to_base64url(challenge_bytes)
                # Check if this challenge appears in the clientDataJSON
                if response_challenge and challenge_b64 in base64url_to_bytes(response_challenge).decode('utf-8', errors='ignore'):
                    challenge_key = key
                    stored_challenge = challenge_bytes
                    break
        
        if not stored_challenge:
            print(f"Available challenge keys: {list(challenges.keys())}")
            raise HTTPException(status_code=400, detail="Challenge not found or expired. Please start registration again.")
        
        print(f"Found matching challenge with key: {challenge_key}")
        
        # Convert the credential data for verification
        registration_credential = RegistrationCredential.parse_raw(json.dumps(credential_data))
        
        print("Parsed registration credential")

        # Verify the registration response
        try:
            verification = verify_registration_response(
                credential=registration_credential,
                expected_challenge=stored_challenge,
                expected_origin=RP_ORIGIN,
                expected_rp_id=RP_ID,
                # require_user_verification=False,  # optional, set if you don't need UV
            )
            print("Verification result: True")
        except Exception as e:
            # Optional: log e for diagnostics
            print(f"Verification result: False ({e})")
            raise HTTPException(status_code=400, detail="Registration verification failed")

        
        # Store the credential
        credential_record = {
            "credential_id": bytes_to_base64url(verification.credential_id),
            "public_key": bytes_to_base64url(verification.credential_public_key),
            "sign_count": verification.sign_count,
            "user_id": user_info["id"]
        }
        
        if username not in user_credentials:
            user_credentials[username] = []
        
        user_credentials[username].append(credential_record)
        
        # Clean up the challenge
        del challenges[challenge_key]
        
        print(f"Successfully registered credential for {username}")
        print(f"Credential ID: {credential_record['credential_id'][:20]}...")
        
        return {
            "verified": True,
            "message": "Registration successful",
            "credential_id": credential_record['credential_id']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Registration complete error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Registration completion failed: {str(e)}")

'''
Starts the WebAuthn authentication (login) process.
It:
1.Validates username.
2. Finds user’s registered credentials.
3. Generates authentication options (PublicKeyCredentialRequestOptions).
4. Stores challenge for later verification.
5. Returns options to frontend for navigator.credentials.get().
'''
@app.post("/authenticate/begin")
async def authenticate_begin(request: AuthenticateBeginRequest):
    username = request.username.strip()
    
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    if username not in user_credentials or not user_credentials[username]:
        raise HTTPException(status_code=404, detail="No credentials found for user")
    
    try:
        print(f"Starting authentication for user: {username}")
        
        # Get user's credentials
        user_creds = user_credentials[username]
        allow_credentials = []
        
        for cred in user_creds:
            allow_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred["credential_id"]),
                    transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE]
                )
            )
        
        print(f"Found {len(allow_credentials)} credentials for authentication")
        
        # Generate authentication options
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        print("Generated authentication options")
        
        # Convert challenge to base64url string for storage and response
        challenge_b64 = bytes_to_base64url(options.challenge) if isinstance(options.challenge, bytes) else options.challenge
        
        # Store challenge
        challenge_key = f"auth_{username}_{challenge_b64[:16]}"
        challenges[challenge_key] = options.challenge  # Store original bytes
        
        print(f"Stored auth challenge with key: {challenge_key}")
        
        # Prepare response
        response_data = {
            "challenge": challenge_b64,
            "timeout": options.timeout,
            "rpId": options.rp_id,
            "allowCredentials": [
                {
                    "id": bytes_to_base64url(cred.id),
                    "type": cred.type,
                    "transports": cred.transports
                }
                for cred in options.allow_credentials
            ] if options.allow_credentials else [],
            "userVerification": options.user_verification
        }
        
        print(f"Returning authentication options for {username}")
        return response_data
        
    except Exception as e:
        print(f"Authentication begin error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")

'''
Completes the WebAuthn authentication process.
It:
1. Receives assertion data from frontend (authenticator’s signed response).
2. Retrieves and validates stored challenge.
3. Verifies assertion using webauthn library and stored credential public key.
4. Confirms user identity if verification succeeds.
5. Returns success/failure (and possibly a session or token).
'''
@app.post("/authenticate/complete")
async def authenticate_complete(request: AuthenticateCompleteRequest):
    username = request.username.strip()
    credential_data = request.credential
    
    try:
        print(f"Completing authentication for user: {username}")
        
        if username not in users:
            raise HTTPException(status_code=400, detail="User not found")
        
        if username not in user_credentials:
            raise HTTPException(status_code=400, detail="No credentials found for user")
        
        # Find the stored challenge
        response_challenge = credential_data.get('response', {}).get('clientDataJSON', '')
        
        challenge_key = None
        stored_challenge = None
        
        # Try to find matching challenge
        for key, challenge_bytes in challenges.items():
            if key.startswith(f"auth_{username}_"):
                challenge_b64 = bytes_to_base64url(challenge_bytes)
                # Check if this challenge appears in the clientDataJSON
                if response_challenge and challenge_b64 in base64url_to_bytes(response_challenge).decode('utf-8', errors='ignore'):
                    challenge_key = key
                    stored_challenge = challenge_bytes
                    break
        
        if not stored_challenge:
            raise HTTPException(status_code=400, detail="Challenge not found or expired. Please start authentication again.")
        
        print(f"Found matching auth challenge with key: {challenge_key}")
        
        # Get the credential ID from the response
        credential_id_b64 = credential_data.get('id') or credential_data.get('rawId')
        if not credential_id_b64:
            raise HTTPException(status_code=400, detail="Credential ID not found in response")
        
        # Find the stored credential
        stored_credential = None
        for cred in user_credentials[username]:
            if cred["credential_id"] == credential_id_b64:
                stored_credential = cred
                break
        
        if not stored_credential:
            raise HTTPException(status_code=400, detail="Credential not found")
        
        print(f"Found stored credential: {stored_credential['credential_id'][:20]}...")
        
        # Convert the credential data for verification
        authentication_credential = AuthenticationCredential.parse_raw(json.dumps(credential_data))

        # Verify the authentication response
        try:
            verification = verify_authentication_response(
                credential=authentication_credential,
                expected_challenge=stored_challenge,
                expected_origin=RP_ORIGIN,
                expected_rp_id=RP_ID,
                credential_public_key=base64url_to_bytes(stored_credential["public_key"]),
                credential_current_sign_count=stored_credential["sign_count"],
            )
            print("Verification result: True")
        except Exception as e:
            # Optional: log e for diagnostics
            print(f"Verification result: False ({e})")
            raise HTTPException(status_code=400, detail="Authentication verification failed")
        
        # Update sign count
        stored_credential["sign_count"] = verification.new_sign_count
        
        # Clean up the challenge
        del challenges[challenge_key]
        
        print(f"Authentication successful for {username}")
        
        return {
            "verified": True,
            "message": "Authentication successful",
            "user": users[username]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Authentication complete error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Authentication completion failed: {str(e)}")

# Debug endpoints
@app.get("/users")
async def get_users():
    """Debug endpoint to list users"""
    return {
        "users": list(users.keys()),
        "user_details": users,
        "credentials_count": {username: len(creds) for username, creds in user_credentials.items()}
    }

@app.delete("/users/{username}")
async def delete_user(username: str):
    """Debug endpoint to delete a user"""
    if username in users:
        del users[username]
    if username in user_credentials:
        del user_credentials[username]
    
    # Clean up any remaining challenges for this user
    keys_to_delete = [key for key in challenges.keys() if f"_{username}_" in key]
    for key in keys_to_delete:
        del challenges[key]
    
    return {"message": f"User {username} deleted"}

@app.get("/debug/challenges")
async def get_challenges():
    """Debug endpoint to see stored challenges"""
    return {
        "challenge_keys": list(challenges.keys()),
        "challenge_count": len(challenges)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)