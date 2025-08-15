#!/usr/bin/env python3
"""
OAuth-protected MCP Server using FastMCP for Render deployment
Using FastMCP's built-in OAuth capabilities with Auth0
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
from datetime import datetime
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse

# Load environment variables from the script's directory
script_dir = os.path.dirname(os.path.abspath(__file__))
env_file = os.path.join(script_dir, 'env')

if os.path.exists(env_file):
    load_dotenv(env_file)
    print(f"Loaded env from: {env_file}", file=sys.stderr)
else:
    print(f"Warning: env file not found at {env_file}", file=sys.stderr)

# Global auth state for external OAuth callback handling
oauth_callback_data = None
oauth_in_progress = False
user_sessions = {}  # Store user sessions by session ID

class Auth0TokenValidator:
    """Validates Auth0 JWT tokens"""
    
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

class Auth0Client:
    """Auth0 OAuth client for server-side flow"""
    
    def __init__(self):
        self.domain = os.environ.get("AUTH0_DOMAIN")
        self.client_id = os.environ.get("AUTH0_CLIENT_ID") 
        self.audience = os.environ.get("AUTH0_AUDIENCE")
        # Use server URL for callback in production
        base_url = os.environ.get("SERVER_URL", "http://localhost:8000")
        self.redirect_uri = f"{base_url}/auth/callback"
        
        if not all([self.domain, self.client_id, self.audience]):
            raise ValueError("Missing Auth0 configuration: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_AUDIENCE required")
    
    def generate_pkce_pair(self):
        """Generate PKCE code verifier and challenge"""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge
    
    def get_authorization_url(self, state: str, code_verifier: str) -> str:
        """Generate Auth0 authorization URL"""
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        auth_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid profile email',
            'audience': self.audience,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'state': state
        }
        
        return f"https://{self.domain}/authorize?" + urlencode(auth_params)
    
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


# Initialize clients
auth_client = Auth0Client()
auth_validator = Auth0TokenValidator()

# Initialize FastMCP server with OAuth callback route
mcp = FastMCP("oauth-mcp-server")

# OAuth callback handler using FastMCP's custom_route
@mcp.custom_route("/auth/callback", methods=["GET"])
async def auth_callback_handler(request: Request):
    """Handle OAuth callback from Auth0"""
    global oauth_callback_data
    
    query_params = dict(request.query_params)
    print(f"🔍 OAuth callback received: {query_params}", file=sys.stderr)
    
    if 'code' in query_params and 'state' in query_params:
        oauth_callback_data = {
            'authorization_code': query_params['code'],
            'state': query_params['state'],
            'error': None
        }
        print(f"✅ Authorization code received: {oauth_callback_data['authorization_code'][:10]}...", file=sys.stderr)
        
        return HTMLResponse("""
        <html><body>
        <h1>🎉 Authentication Successful!</h1>
        <p>You can now close this window and return to Claude Desktop.</p>
        <p>Your MCP tools are now ready to use!</p>
        <script>setTimeout(() => window.close(), 3000);</script>
        </body></html>
        """)
    elif 'error' in query_params:
        oauth_callback_data = {
            'authorization_code': None,
            'state': query_params.get('state'),
            'error': query_params['error']
        }
        print(f"❌ OAuth error: {oauth_callback_data['error']}", file=sys.stderr)
        
        return HTMLResponse(f"""
        <html><body>
        <h1>❌ Authentication Error</h1>
        <p>Error: {query_params['error']}</p>
        <p>Description: {query_params.get('error_description', 'Unknown error')}</p>
        </body></html>
        """)
    else:
        print("❌ No code or error in callback", file=sys.stderr)
        return HTMLResponse("""
        <html><body>
        <h1>❌ Authentication Error</h1>
        <p>No authorization code received</p>
        </body></html>
        """)

# Auth initiation route for easy testing
@mcp.custom_route("/auth/login", methods=["GET"])
async def auth_login_handler(request: Request):
    """Initiate OAuth flow"""
    state = secrets.token_urlsafe(16)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Store PKCE verifier for this state (in production, use proper session storage)
    user_sessions[state] = {
        'code_verifier': code_verifier,
        'timestamp': datetime.now().isoformat()
    }
    
    auth_url = auth_client.get_authorization_url(state, code_verifier)
    return RedirectResponse(url=auth_url, status_code=302)

def get_user_context(session_token: str) -> Optional[Dict[str, Any]]:
    """Get user context from session token"""
    try:
        # In a real implementation, this would validate the session token
        # and return user info from a secure session store
        user_info = auth_validator.validate_token(session_token)
        if user_info:
            detailed_user_info = auth_validator.get_user_info(session_token)
            if detailed_user_info:
                return {
                    'user_id': user_info.get('sub'),
                    'email': detailed_user_info.get('email'),
                    'name': detailed_user_info.get('name') or detailed_user_info.get('nickname'),
                    'access_token': session_token
                }
        return None
    except Exception as e:
        print(f"Error getting user context: {e}", file=sys.stderr)
        return None

@mcp.tool()
def echo_message(message: str, access_token: str = "") -> str:
    """
    Echo back a message with OAuth authentication.
    
    Args:
        message: The message to echo back
        access_token: OAuth access token (required for authentication)
        
    Returns:
        Echoed message with authenticated user info
    """
    if not access_token:
        base_url = os.environ.get("SERVER_URL", "http://localhost:8000")
        return f"❌ Authentication required. Please visit {base_url}/auth/login to authenticate, then provide your access token."
    
    # Validate the access token
    user_context = get_user_context(access_token)
    if not user_context:
        return "❌ Invalid access token. Please re-authenticate."
    
    user_id = user_context.get('user_id', 'Unknown')
    user_name = user_context.get('name') or user_context.get('email', 'User')
    
    # Debug: Print user info to stderr
    print(f"🔍 Debug - User ID: {user_id}", file=sys.stderr)
    print(f"🔍 Debug - User name: {user_name}", file=sys.stderr)
    
    response = f"🔐 Authenticated User: {user_name}\n🆔 User ID: {user_id}\n💬 Your message: '{message}'"
    print(f"📝 Authenticated echo from {user_name} ({user_id}): {response}", file=sys.stderr)
    return response

@mcp.tool()
def start_auth() -> str:
    """
    Start OAuth authentication flow.
    
    Returns:
        Authentication URL for the user to visit
    """
    base_url = os.environ.get("SERVER_URL", "http://localhost:8000")
    auth_url = f"{base_url}/auth/login"
    
    return f"🔐 Please visit this URL to authenticate: {auth_url}\n\nAfter authentication, you'll receive an access token to use with other tools."

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0" if os.environ.get("RENDER") else "localhost"
    
    print("🚀 OAuth-protected FastMCP server starting...", file=sys.stderr)
    print("🔐 Server-side OAuth with Auth0 integration", file=sys.stderr)
    print("🛠️  Available tools: start_auth, echo_message (OAuth protected)", file=sys.stderr)
    print("🌐 Using streamable HTTP transport...", file=sys.stderr)
    print(f"📡 Server will be available at: http://{host}:{port}/mcp", file=sys.stderr)
    print(f"🔓 Auth login URL: http://{host}:{port}/auth/login", file=sys.stderr)
    print(f"📞 Auth callback URL: http://{host}:{port}/auth/callback", file=sys.stderr)
    
    # Run with streamable HTTP transport
    mcp.run(transport="streamable-http", host=host, port=port)