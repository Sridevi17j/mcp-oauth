#!/usr/bin/env python3
"""
Simple OAuth-protected MCP Server using FastMCP
"""

import os
import sys
import json
import jwt
import requests
import asyncio
import webbrowser
import base64
import hashlib
import secrets
from typing import Any, Dict, Optional
from urllib.parse import urlencode, parse_qs, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from datetime import datetime
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load environment variables from the script's directory
script_dir = os.path.dirname(os.path.abspath(__file__))
env_file = os.path.join(script_dir, 'env')

if os.path.exists(env_file):
    load_dotenv(env_file)
    print(f"Loaded env from: {env_file}", file=sys.stderr)
else:
    print(f"Warning: env file not found at {env_file}", file=sys.stderr)

# Initialize FastMCP server
mcp = FastMCP("simple-oauth-server")

# Global auth state
user_access_token = None
user_name = None
oauth_in_progress = False

class AuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback"""
    
    def do_GET(self):
        # Parse the authorization code from callback
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        if 'code' in query_params:
            self.server.authorization_code = query_params['code'][0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'''
            <html><body>
            <h1>Authentication Successful!</h1>
            <p>You can now close this window and return to Claude Desktop.</p>
            <script>setTimeout(() => window.close(), 3000);</script>
            </body></html>
            ''')
        elif 'error' in query_params:
            self.server.error = query_params['error'][0]
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f'''
            <html><body>
            <h1>Authentication Error</h1>
            <p>Error: {query_params['error'][0]}</p>
            </body></html>
            '''.encode())
        
        # Signal the server to stop
        Thread(target=self.server.shutdown).start()
    
    def log_message(self, format, *args):
        # Suppress default logging to keep stdio clean
        pass

class Auth0Client:
    """Auth0 OAuth client with browser-based PKCE flow"""
    
    def __init__(self):
        self.domain = os.environ.get("AUTH0_DOMAIN")
        self.client_id = os.environ.get("AUTH0_CLIENT_ID") 
        self.audience = os.environ.get("AUTH0_AUDIENCE")
        self.redirect_uri = "http://localhost:8080/callback"
        
        if not all([self.domain, self.client_id, self.audience]):
            raise ValueError("Missing Auth0 configuration: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_AUDIENCE required")
    
    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge
    
    def authenticate(self) -> Optional[str]:
        """Perform browser-based OAuth authentication"""
        global oauth_in_progress
        
        if oauth_in_progress:
            print("OAuth flow already in progress...", file=sys.stderr)
            return None
            
        oauth_in_progress = True
        
        try:
            print("🔐 Starting Auth0 authentication...", file=sys.stderr)
            
            # Generate PKCE parameters
            code_verifier, code_challenge = self.generate_pkce_pair()
            
            # Build authorization URL
            auth_params = {
                'response_type': 'code',
                'client_id': self.client_id,
                'redirect_uri': self.redirect_uri,
                'scope': 'openid profile email',
                'audience': self.audience,
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
                'state': secrets.token_urlsafe(16)
            }
            
            auth_url = f"https://{self.domain}/authorize?" + urlencode(auth_params)
            
            print(f"🌐 Opening browser for authentication...", file=sys.stderr)
            
            # Start local callback server
            server = HTTPServer(('localhost', 8080), AuthCallbackHandler)
            server.authorization_code = None
            server.error = None
            
            # Open browser
            webbrowser.open(auth_url)
            
            print("⏳ Waiting for authorization...", file=sys.stderr)
            
            # Handle callback with timeout
            server.timeout = 60  # 60 second timeout
            server.handle_request()
            
            if hasattr(server, 'error') and server.error:
                print(f"❌ Authentication failed: {server.error}", file=sys.stderr)
                return None
            
            if not hasattr(server, 'authorization_code') or not server.authorization_code:
                print("❌ No authorization code received", file=sys.stderr)
                return None
            
            # Exchange code for token
            return self.exchange_code_for_token(server.authorization_code, code_verifier)
            
        finally:
            oauth_in_progress = False
    
    def exchange_code_for_token(self, auth_code: str, code_verifier: str) -> Optional[str]:
        """Exchange authorization code for access token"""
        print("🔄 Exchanging code for token...", file=sys.stderr)
        
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': code_verifier
        }
        
        try:
            response = requests.post(
                f"https://{self.domain}/oauth/token",
                json=token_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            
            token_response = response.json()
            access_token = token_response.get('access_token')
            
            if access_token:
                print("✅ Authentication successful!", file=sys.stderr)
                return access_token
            else:
                print("❌ No access token received", file=sys.stderr)
                return None
                
        except Exception as e:
            print(f"❌ Token exchange failed: {e}", file=sys.stderr)
            return None

class Auth0TokenValidator:
    def __init__(self):
        self.domain = os.environ.get("AUTH0_DOMAIN")
        self.audience = os.environ.get("AUTH0_AUDIENCE") 
        self.algorithms = ["RS256"]
        self.jwks_uri = f"https://{self.domain}/.well-known/jwks.json"
        self.userinfo_uri = f"https://{self.domain}/userinfo"
        self._jwks_cache = None
    
    def get_jwks(self):
        """Get JWKS from Auth0"""
        if self._jwks_cache is None:
            try:
                response = requests.get(self.jwks_uri, timeout=10)
                response.raise_for_status()
                self._jwks_cache = response.json()
            except Exception as e:
                print(f"Failed to get JWKS: {e}", file=sys.stderr)
                return None
        return self._jwks_cache
    
    def get_signing_key(self, kid):
        """Get signing key for token verification"""
        jwks = self.get_jwks()
        if not jwks:
            return None
            
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        return None
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate Auth0 JWT token"""
        try:
            # Decode token header to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                return None
            
            # Get signing key
            signing_key = self.get_signing_key(kid)
            if not signing_key:
                return None
            
            # Verify token
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=f"https://{self.domain}/"
            )
            
            return payload
            
        except Exception as e:
            print(f"Token validation error: {e}", file=sys.stderr)
            return None
    
    def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user info from Auth0 /userinfo endpoint"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(self.userinfo_uri, headers=headers, timeout=10)
            response.raise_for_status()
            
            user_info = response.json()
            print(f"🔍 User info from /userinfo: {user_info}", file=sys.stderr)
            return user_info
            
        except Exception as e:
            print(f"Failed to get user info: {e}", file=sys.stderr)
            return None

# Initialize clients
auth_client = Auth0Client()
auth_validator = Auth0TokenValidator()

def ensure_authenticated() -> bool:
    """Ensure user is authenticated, trigger auth flow if needed"""
    global user_access_token, user_name
    
    if not user_access_token:
        print("🔐 No active session. Starting authentication...", file=sys.stderr)
        user_access_token = auth_client.authenticate()
        
        if user_access_token:
            # Validate token and get user info
            user_info = auth_validator.validate_token(user_access_token)
            if user_info:
                # Get detailed user info from Auth0 /userinfo endpoint
                detailed_user_info = auth_validator.get_user_info(user_access_token)
                if detailed_user_info:
                    # Extract user name/email from userinfo endpoint
                    user_name = detailed_user_info.get('email') or detailed_user_info.get('name') or detailed_user_info.get('nickname') or user_info.get('sub', 'User')
                else:
                    # Fallback to token info
                    user_name = user_info.get('email') or user_info.get('name') or user_info.get('sub', 'User')
                
                print(f"👋 Hello {user_name}!", file=sys.stderr)
                return True
        
        return False
    
    return True

@mcp.tool()
def echo_message(message: str) -> str:
    """
    Echo back a message with OAuth authentication.
    Will trigger browser-based Auth0 login if not authenticated.
    
    Args:
        message: The message to echo back
        
    Returns:
        Echoed message with authenticated user info
    """
    global user_access_token, user_name
    
    # Ensure user is authenticated (will trigger browser auth if needed)
    if not ensure_authenticated():
        return "❌ Authentication failed or cancelled. Please try again."
    
    # Validate current token
    user_info = auth_validator.validate_token(user_access_token)
    if not user_info:
        # Token might be expired, clear it and retry once
        user_access_token = None
        user_name = None
        
        if not ensure_authenticated():
            return "❌ Re-authentication failed. Please try again."
        
        user_info = auth_validator.validate_token(user_access_token)
        
        if not user_info:
            return "❌ Token validation failed. Please try again."
    
    # Echo the message with user's name and ID
    user_id = user_info.get('sub', 'Unknown')
    
    # Debug: Print all user info to stderr
    print(f"🔍 Debug - User info keys: {list(user_info.keys())}", file=sys.stderr)
    print(f"🔍 Debug - Full user info: {user_info}", file=sys.stderr)
    print(f"🔍 Debug - User ID (sub): {user_id}", file=sys.stderr)
    print(f"🔍 Debug - User name: {user_name}", file=sys.stderr)
    
    response = f"🔐 Authenticated User: {user_name}\n🆔 User ID: {user_id}\n💬 Your message: '{message}'"
    print(f"📝 Authenticated echo from {user_name} ({user_id}): {response}", file=sys.stderr)
    return response

if __name__ == "__main__":
    print("🚀 OAuth-protected FastMCP server starting...", file=sys.stderr)
    print("🔐 Browser authentication will trigger when tool is used", file=sys.stderr)
    print("🛠️  Available tool: echo_message (OAuth protected)", file=sys.stderr)
    print("🌐 Using streamable HTTP transport...", file=sys.stderr)
    print("📡 Server will be available at: http://localhost:8000/mcp", file=sys.stderr)
    
    # Run with streamable HTTP transport (new standard, not deprecated SSE)
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)