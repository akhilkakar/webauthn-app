"use client";

import React, { useState, useEffect } from 'react';
import { User, Shield, Key, CheckCircle, XCircle, Loader } from 'lucide-react';

// Utility functions for WebAuthn
const base64URLStringToBuffer = (base64URLString) => {
  const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  const binary = atob(padded);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return buffer;
};

const bufferToBase64URLString = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }
  const base64String = btoa(str);
  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

export default function WebAuthnApp() {
  const [user, setUser] = useState(null);
  const [username, setUsername] = useState('');
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);
  const [registeredUsers, setRegisteredUsers] = useState([]);

  const API_BASE = 'http://localhost:8000'; // Python backend URL

  useEffect(() => {
    // Load registered users from memory (in a real app, this would be from your backend)
    const users = JSON.parse(localStorage.getItem('webauthn_users') || '[]');
    setRegisteredUsers(users);
  }, []);

  const handleRegister = async () => {
    if (!username.trim()) {
      setStatus('Please enter a username');
      return;
    }

    setLoading(true);
    setStatus('Starting registration...');

    try {
      // Step 1: Get registration options from backend
      const optionsResponse = await fetch(`${API_BASE}/register/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });

      if (!optionsResponse.ok) {
        throw new Error('Failed to get registration options');
      }

      const options = await optionsResponse.json();
      
      // Step 2: Convert challenge and user ID from base64url
      const publicKeyCredentialCreationOptions = {
        ...options.publicKey,
        challenge: base64URLStringToBuffer(options.publicKey.challenge),
        user: {
          ...options.publicKey.user,
          id: base64URLStringToBuffer(options.publicKey.user.id)
        }
      };

      setStatus('Please use your authenticator...');

      // Step 3: Create credential
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      });

      setStatus('Completing registration...');

      // Step 4: Send credential to backend
      const credentialData = {
        id: credential.id,
        rawId: bufferToBase64URLString(credential.rawId),
        response: {
          clientDataJSON: bufferToBase64URLString(credential.response.clientDataJSON),
          attestationObject: bufferToBase64URLString(credential.response.attestationObject)
        },
        type: credential.type
      };

      const verifyResponse = await fetch(`${API_BASE}/register/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          credential: credentialData,
          challenge: options.publicKey.challenge
        })
      });

      if (!verifyResponse.ok) {
        throw new Error('Failed to verify registration');
      }

      const result = await verifyResponse.json();
      
      // Store user locally (in real app, this would be handled by backend)
      const newUser = { username, credentialId: credential.id, registered: true };
      const updatedUsers = [...registeredUsers, newUser];
      setRegisteredUsers(updatedUsers);
      localStorage.setItem('webauthn_users', JSON.stringify(updatedUsers));

      setStatus('Registration successful!');
      setUser(newUser);
      setUsername('');

    } catch (error) {
      console.error('Registration failed:', error);
      setStatus(`Registration failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    if (!username.trim()) {
      setStatus('Please enter a username');
      return;
    }

    setLoading(true);
    setStatus('Starting login...');

    try {
      // Step 1: Get authentication options from backend
      const optionsResponse = await fetch(`${API_BASE}/authenticate/begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });

      if (!optionsResponse.ok) {
        throw new Error('Failed to get authentication options');
      }

      const options = await optionsResponse.json();

      // Step 2: Convert challenge and allowed credentials
      const publicKeyCredentialRequestOptions = {
        ...options.publicKey,
        challenge: base64URLStringToBuffer(options.publicKey.challenge),
        allowCredentials: options.publicKey.allowCredentials?.map(cred => ({
          ...cred,
          id: base64URLStringToBuffer(cred.id)
        })) || []
      };

      setStatus('Please use your authenticator...');

      // Step 3: Get credential
      const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions
      });

      setStatus('Verifying login...');

      // Step 4: Send assertion to backend
      const assertionData = {
        id: assertion.id,
        rawId: bufferToBase64URLString(assertion.rawId),
        response: {
          authenticatorData: bufferToBase64URLString(assertion.response.authenticatorData),
          clientDataJSON: bufferToBase64URLString(assertion.response.clientDataJSON),
          signature: bufferToBase64URLString(assertion.response.signature),
          userHandle: assertion.response.userHandle ? bufferToBase64URLString(assertion.response.userHandle) : null
        },
        type: assertion.type
      };

      const verifyResponse = await fetch(`${API_BASE}/authenticate/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          assertion: assertionData,
          challenge: options.publicKey.challenge
        })
      });

      if (!verifyResponse.ok) {
        throw new Error('Authentication failed');
      }

      const result = await verifyResponse.json();
      
      const existingUser = registeredUsers.find(u => u.username === username);
      if (existingUser) {
        setUser(existingUser);
        setStatus('Login successful!');
        setUsername('');
      } else {
        setStatus('User not found locally');
      }

    } catch (error) {
      console.error('Login failed:', error);
      setStatus(`Login failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setUser(null);
    setStatus('Logged out successfully');
  };

  const clearUsers = () => {
    setRegisteredUsers([]);
    localStorage.removeItem('webauthn_users');
    setUser(null);
    setStatus('All users cleared');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-md mx-auto bg-white rounded-xl shadow-lg p-8">
        <div className="text-center mb-8">
          <Shield className="mx-auto h-12 w-12 text-indigo-600 mb-4" />
          <h1 className="text-2xl font-bold text-gray-900">WebAuthn Demo</h1>
          <p className="text-gray-600 mt-2">Secure authentication with your device</p>
        </div>

        {user ? (
          <div className="text-center">
            <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
              <CheckCircle className="mx-auto h-8 w-8 text-green-600 mb-2" />
              <h2 className="text-lg font-semibold text-green-800">Welcome back!</h2>
              <p className="text-green-700">Logged in as: <strong>{user.username}</strong></p>
            </div>
            
            <button
              onClick={handleLogout}
              className="w-full bg-red-600 text-white py-2 px-4 rounded-lg font-semibold hover:bg-red-700 transition-colors"
            >
              Logout
            </button>
          </div>
        ) : (
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter username"
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  disabled={loading}
                />
              </div>
            </div>

            <div className="space-y-3">
              <button
                onClick={handleRegister}
                disabled={loading || !username.trim()}
                className="w-full bg-indigo-600 text-white py-2 px-4 rounded-lg font-semibold hover:bg-indigo-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors flex items-center justify-center"
              >
                {loading ? <Loader className="animate-spin h-5 w-5 mr-2" /> : <Key className="h-5 w-5 mr-2" />}
                Register New Account
              </button>

              <button
                onClick={handleLogin}
                disabled={loading || !username.trim()}
                className="w-full bg-green-600 text-white py-2 px-4 rounded-lg font-semibold hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors flex items-center justify-center"
              >
                {loading ? <Loader className="animate-spin h-5 w-5 mr-2" /> : <Shield className="h-5 w-5 mr-2" />}
                Login
              </button>
            </div>
          </div>
        )}

        {status && (
          <div className={`mt-4 p-3 rounded-lg text-sm ${
            status.includes('successful') || status.includes('Welcome') 
              ? 'bg-green-50 text-green-800 border border-green-200' 
              : status.includes('failed') || status.includes('error')
              ? 'bg-red-50 text-red-800 border border-red-200'
              : 'bg-blue-50 text-blue-800 border border-blue-200'
          }`}>
            {status.includes('failed') || status.includes('error') ? (
              <XCircle className="inline h-4 w-4 mr-1" />
            ) : status.includes('successful') ? (
              <CheckCircle className="inline h-4 w-4 mr-1" />
            ) : null}
            {status}
          </div>
        )}

        {registeredUsers.length > 0 && (
          <div className="mt-6 p-4 bg-gray-50 rounded-lg">
            <h3 className="font-semibold text-gray-800 mb-2">Registered Users:</h3>
            <ul className="text-sm text-gray-600 space-y-1">
              {registeredUsers.map((u, i) => (
                <li key={i} className="flex items-center">
                  <User className="h-4 w-4 mr-2" />
                  {u.username}
                </li>
              ))}
            </ul>
            <button
              onClick={clearUsers}
              className="mt-2 text-xs text-red-600 hover:text-red-800 underline"
            >
              Clear all users
            </button>
          </div>
        )}

        <div className="mt-6 text-xs text-gray-500 text-center">
          <p>Make sure your Python backend is running on localhost:8000</p>
          <p>Requires HTTPS in production or localhost for development</p>
        </div>
      </div>
    </div>
  );
}