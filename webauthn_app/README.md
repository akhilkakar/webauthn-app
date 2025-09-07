# WebAuthn Login App Setup Guide

This is a complete WebAuthn authentication system with a Next.js frontend and Python FastAPI backend.

## Features

- ✅ User registration with WebAuthn
- ✅ Passwordless login using biometrics/security keys
- ✅ Cross-platform support (Windows Hello, Touch ID, security keys, etc.)
- ✅ Secure challenge-response authentication
- ✅ Modern UI with status feedback

## Prerequisites

- Node.js 16+ and npm
- Python 3.8+
- HTTPS or localhost (required for WebAuthn)
- A WebAuthn-compatible device (most modern devices support this)

## Backend Setup (Python FastAPI)

### 1. Create Python Environment

```bash
# Create virtual environment
python -m venv webauthn_env

# Activate it (Windows)
webauthn_env\Scripts\activate

# Activate it (macOS/Linux)
source webauthn_env/bin/activate
```

### 2. Install Dependencies

```bash
pip install fastapi uvicorn webauthn python-multipart
```

### 3. Save Backend Code

Save the Python backend code as `main.py` in your project directory.

### 4. Run Backend Server

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The backend will be available at `http://localhost:8000`

## Frontend Setup (Next.js)

### 1. Create Next.js Project

```bash
npx create-next-app@latest webauthn-frontend
cd webauthn-frontend
```

### 2. Install Additional Dependencies

```bash
npm install lucide-react
```

### 3. Replace Default Component

Replace the contents of `pages/index.js` (or `app/page.js` for App Router) with the React component code provided.

### 4. Run Frontend

```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Usage Instructions

### Registration
1. Enter a username in the input field
2. Click "Register New Account"
3. Follow your device's prompts (fingerprint, face recognition, security key, etc.)
4. Registration complete!

### Login
1. Enter your registered username
2. Click "Login"
3. Authenticate with your device
4. You're logged in!

## Supported Authenticators

- **Biometrics**: Fingerprint readers, Face ID, Windows Hello
- **Security Keys**: YubiKey, Google Titan, SoloKeys
- **Platform**: Built-in TPM, Secure Enclave
- **Cross-platform**: FIDO2/WebAuthn compatible devices

## Development Notes

### Security Considerations for Production

1. **HTTPS Required**: WebAuthn requires HTTPS in production
2. **Domain Configuration**: Update `RP_ID` and `RP_ORIGIN` in backend
3. **Database**: Replace in-memory storage with proper database
4. **Error Handling**: Add comprehensive error handling
5. **Rate Limiting**: Implement rate limiting for API endpoints
6. **Session Management**: Add proper session/token management

### Configuration Variables

In `main.py`, update these for production:

```python
RP_ID = "your-domain.com"        # Your actual domain
RP_NAME = "Your App Name"        # Your application name
RP_ORIGIN = "https://your-domain.com"  # Your frontend URL
```

### Database Schema (for production)

```sql
-- Users table
CREATE TABLE users (
    id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Credentials table
CREATE TABLE user_credentials (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) REFERENCES users(id),
    credential_id TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## API Endpoints

### Registration
- `POST /register/begin` - Start registration process
- `POST /register/complete` - Complete registration with credential

### Authentication
- `POST /authenticate/begin` - Start authentication process
- `POST /authenticate/complete` - Complete authentication with assertion

### Utility
- `GET /users` - List registered users (debug only)
- `DELETE /users/{username}` - Delete user (debug only)

## Troubleshooting

### Common Issues

1. **"WebAuthn not supported"**
   - Ensure you're using HTTPS or localhost
   - Check browser compatibility (Chrome 67+, Firefox 60+, Safari 14+)

2. **"Registration failed"**
   - Make sure backend is running on port 8000
   - Check CORS configuration
   - Verify authenticator is properly connected

3. **"Challenge invalid"**
   - Challenges expire after 60 seconds
   - Don't refresh page during authentication flow

4. **"User not found"**
   - Make sure user was successfully registered
   - Check browser's local storage for user data

### Browser Support

| Browser | Version | Support |
|---------|---------|---------|
| Chrome  | 67+     | ✅ Full  |
| Firefox | 60+     | ✅ Full  |
| Safari  | 14+     | ✅ Full  |
| Edge    | 79+     | ✅ Full  |

### Testing Authenticators

- **Desktop**: Windows Hello, Touch ID, YubiKey
- **Mobile**: Fingerprint, Face ID, PIN
- **Cross-platform**: Any FIDO2 security key

## Advanced Features (Optional Enhancements)

Not implemented in the project.

### 1. Multiple Credentials per User

```python
# Allow users to register multiple authenticators
@app.post("/register/additional")
async def register_additional_credential(request: RegisterBeginRequest):
    # Implementation for adding additional credentials
    pass
```

### 2. Credential Management

```python
# List user's credentials
@app.get("/user/{username}/credentials")
async def list_user_credentials(username: str):
    # Return list of user's registered credentials
    pass

# Delete specific credential
@app.delete("/user/{username}/credentials/{credential_id}")
async def delete_credential(username: str, credential_id: str):
    # Remove specific credential
    pass
```

### 3. User Verification Requirements

Update authenticator selection for stricter security:

```python
authenticator_selection=AuthenticatorSelectionCriteria(
    user_verification=UserVerificationRequirement.REQUIRED,  # Always require biometrics/PIN
    authenticator_attachment=AuthenticatorAttachment.PLATFORM,  # Only platform authenticators
    resident_key=ResidentKeyRequirement.REQUIRED  # Require resident keys
)
```

## Production Deployment

### 1. Environment Variables

Create `.env` file:

```env
# Backend
WEBAUTHN_RP_ID=your-domain.com
WEBAUTHN_RP_NAME=Your App Name
WEBAUTHN_RP_ORIGIN=https://your-domain.com
DATABASE_URL=postgresql://user:pass@host:port/db

# Frontend
NEXT_PUBLIC_API_URL=https://api.your-domain.com
```

### 2. Docker Configuration

**Backend Dockerfile:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Frontend Dockerfile:**

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
```

### 3. SSL/TLS Configuration

WebAuthn requires HTTPS in production. Use:
- Let's Encrypt for free SSL certificates
- Cloudflare for SSL termination
- AWS Certificate Manager for AWS deployments

## Security Best Practices

1. **Server-side Validation**: Always validate credentials on server
2. **Challenge Expiration**: Set reasonable timeout values (60 seconds)
3. **Origin Verification**: Verify request origin matches expected domain
4. **Rate Limiting**: Prevent brute force attacks
5. **Audit Logging**: Log authentication attempts
6. **Backup Authentication**: Provide alternative login method for account recovery

## Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [FIDO Alliance](https://fidoalliance.org/)
- [Can I Use WebAuthn](https://caniuse.com/webauthn)
- [WebAuthn.io Demo](https://webauthn.io/)

## License

This example code is provided for educational purposes. Use appropriate licenses for production applications.