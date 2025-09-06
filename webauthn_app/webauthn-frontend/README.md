# Setup Instructions

## Prerequisites
- AWS account
- Python 3.9+ installed
- Node.js 20+ installed
- Git installed

## Clone the repository
```bash
git clone https://github.com/your-username/passwordless-sso-ai-risk.git
cd passwordless-sso-ai-risk
```

## Backend Setup
1. Navigate to the backend folder:
   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # On macOS/Linux
   venv\Scripts\activate      # On Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Start the backend server:
   ```bash
   python -m uvicorn main:app --reload
   ```

   The backend will run on [http://localhost:8000](http://localhost:8000).

## Frontend Setup
1. Navigate to the frontend folder:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the frontend:
   ```bash
   npm run dev
   ```

   The frontend will run on [http://localhost:3000](http://localhost:3000).

## Notes
- Make sure the backend is running on port **8000** before starting the frontend.
- For production, ensure HTTPS is enabled for WebAuthn.
