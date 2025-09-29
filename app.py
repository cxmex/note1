# requirements.txt dependencies:
# fastapi
# uvicorn
# python-multipart
# httpx
# python-jose[cryptography]
# supabase
# python-dotenv
# google-auth

import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import httpx
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from supabase import create_client, Client
from dotenv import load_dotenv
import jwt
from pydantic import BaseModel
from google.auth.transport import requests
from google.oauth2 import id_token

load_dotenv()

# Configuration with validation
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Validate required environment variables
required_env_vars = {
    "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
    "SUPABASE_URL": SUPABASE_URL,
    "SUPABASE_ANON_KEY": SUPABASE_KEY,
}

missing_vars = [var for var, value in required_env_vars.items() if not value]
if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Initialize FastAPI
app = FastAPI(title="Nota Auth API")

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=JWT_SECRET)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000", "http://127.0.0.1:3000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Supabase
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Supabase client initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize Supabase client: {e}")
    raise

# Security
security = HTTPBearer()

# In-memory session storage (use Redis in production)
user_sessions: Dict[str, Dict[str, Any]] = {}

# Pydantic models
class GoogleAuthRequest(BaseModel):
    google_token: str

class User(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    profile_picture_url: Optional[str] = None
    is_active: bool = True
    created_at: datetime
    last_login_at: Optional[datetime] = None

class SessionResponse(BaseModel):
    success: bool
    session_token: str
    user: Dict[str, Any]

# Helper functions
async def verify_google_token(token: str) -> Dict[str, Any]:
    """Verify Google ID token and return user info"""
    try:
        # Verify the token with Google
        idinfo = id_token.verify_oauth2_token(
            token, requests.Request(), GOOGLE_CLIENT_ID
        )
        
        # Check if token is from the correct app
        if idinfo['aud'] != GOOGLE_CLIENT_ID:
            raise ValueError('Wrong audience.')
            
        return {
            'id': idinfo['sub'],
            'email': idinfo['email'],
            'name': idinfo.get('name'),
            'picture': idinfo.get('picture'),
            'email_verified': idinfo.get('email_verified', False)
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid Google token: {str(e)}")

async def create_or_get_user(user_info: Dict[str, Any]) -> Dict[str, Any]:
    """Create new user or get existing user from Google user info"""
    email = user_info.get('email')
    
    # Check if user exists
    existing_user = supabase.table('nota_users').select('*').eq('email', email).execute()
    
    if existing_user.data:
        # Update existing user
        user_id = existing_user.data[0]['id']
        updated_user = supabase.table('nota_users').update({
            'full_name': user_info.get('name'),
            'profile_picture_url': user_info.get('picture'),
            'last_login_at': datetime.utcnow().isoformat()
        }).eq('id', user_id).execute()
        
        return updated_user.data[0]
    else:
        # Create new user
        new_user = supabase.table('nota_users').insert({
            'email': email,
            'full_name': user_info.get('name'),
            'profile_picture_url': user_info.get('picture'),
            'last_login_at': datetime.utcnow().isoformat()
        }).execute()
        
        return new_user.data[0]

def generate_session_token() -> str:
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def create_access_token(user_id: str, expires_delta: timedelta = None) -> str:
    """Create JWT access token"""
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode = {"sub": user_id, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")
    return encoded_jwt

def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify session token and return user data"""
    session_data = user_sessions.get(token)
    if not session_data:
        return None
    
    # Check if session is expired
    if datetime.utcnow() > session_data.get('expires_at', datetime.utcnow()):
        del user_sessions[token]
        return None
    
    return session_data

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user from session token"""
    session_data = verify_session_token(credentials.credentials)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return session_data

# Routes
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the authentication test interface"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Nota Auth - Google Sign In</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://accounts.google.com/gsi/client" async defer></script>
    </head>
    <body class="bg-gradient-to-br from-blue-500 to-purple-600 min-h-screen flex items-center justify-center p-4">
        <div class="max-w-md w-full">
            <!-- Main Card -->
            <div class="bg-white/25 backdrop-blur-lg border border-white/20 rounded-2xl p-8 shadow-2xl">
                <div class="text-center mb-8">
                    <h1 class="text-3xl font-bold text-white mb-2">Nota Auth</h1>
                    <p class="text-white/80">Sign in with your Google account</p>
                </div>

                <!-- Auth Status -->
                <div id="auth-status" class="mb-6">
                    <div id="logged-out" class="text-center">
                        <div class="bg-white/20 rounded-lg p-4 mb-4">
                            <p class="text-white/90 text-sm">Not authenticated</p>
                        </div>
                        
                        <!-- Google Sign In Button -->
                        <div id="g_id_onload"
                             data-client_id=\"""" + GOOGLE_CLIENT_ID + """\"
                             data-callback="handleCredentialResponse"
                             data-auto_prompt="false">
                        </div>
                        <div class="g_id_signin" 
                             data-type="standard" 
                             data-size="large" 
                             data-theme="outline" 
                             data-text="sign_in_with"
                             data-shape="rectangular"
                             data-logo_alignment="left">
                        </div>
                    </div>

                    <div id="logged-in" class="hidden">
                        <div class="bg-green-500/20 border border-green-500/30 rounded-lg p-4 mb-4">
                            <div class="flex items-center space-x-3">
                                <img id="user-avatar" src="" alt="User Avatar" class="w-12 h-12 rounded-full border-2 border-white/20">
                                <div>
                                    <p id="user-name" class="text-white font-semibold"></p>
                                    <p id="user-email" class="text-white/80 text-sm"></p>
                                </div>
                            </div>
                        </div>

                        <div class="space-y-2 mb-4">
                            <button 
                                onclick="getUserInfo()" 
                                class="w-full bg-blue-500 hover:bg-blue-600 text-white font-medium py-2 px-4 rounded-lg transition duration-200"
                            >
                                Get User Info
                            </button>
                            
                            <button 
                                onclick="logout()" 
                                class="w-full bg-red-500 hover:bg-red-600 text-white font-medium py-2 px-4 rounded-lg transition duration-200"
                            >
                                Logout
                            </button>
                        </div>
                    </div>
                </div>

                <!-- API Response Display -->
                <div id="response-container" class="hidden">
                    <div class="bg-black/20 rounded-lg p-4">
                        <div class="flex justify-between items-center mb-2">
                            <h3 class="text-white font-semibold">API Response</h3>
                            <button 
                                onclick="clearResponse()" 
                                class="text-white/60 hover:text-white text-sm"
                            >
                                Clear
                            </button>
                        </div>
                        <pre id="api-response" class="text-green-300 text-sm overflow-x-auto whitespace-pre-wrap"></pre>
                    </div>
                </div>
            </div>

            <!-- Debug Info -->
            <div class="bg-white/25 backdrop-blur-lg border border-white/20 rounded-lg p-4 mt-4">
                <h3 class="text-white font-semibold mb-2">Debug Info</h3>
                <div class="text-white/70 text-sm space-y-1">
                    <p>API Base: <span id="api-base" class="text-green-300">http://localhost:8000</span></p>
                    <p>Session Status: <span id="session-status" class="text-green-300">No session</span></p>
                </div>
            </div>
        </div>

        <script>
            // Configuration
            const API_BASE = 'http://localhost:8000';
            let currentSessionToken = null;
            let currentUser = null;

            // Handle Google Sign In
            async function handleCredentialResponse(response) {
                console.log("Encoded JWT ID token: " + response.credential);
                
                try {
                    const result = await fetch(`${API_BASE}/api/auth/google`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            google_token: response.credential
                        })
                    });

                    const data = await result.json();
                    console.log("Server response:", data);
                    
                    if (result.ok && data.success) {
                        currentSessionToken = data.session_token;
                        currentUser = data.user;
                        showLoggedIn(data.user);
                        showResponse(data);
                    } else {
                        console.error("Auth failed:", data);
                        showResponse({
                            error: true, 
                            message: data.detail || data.message || 'Authentication failed',
                            status: result.status
                        });
                    }
                } catch (error) {
                    console.error('Network/Parse error:', error);
                    showResponse({error: true, message: `Network error: ${error.message}`});
                }
            }

            // Show logged in state
            function showLoggedIn(user) {
                document.getElementById('logged-out').classList.add('hidden');
                document.getElementById('logged-in').classList.remove('hidden');
                
                document.getElementById('user-name').textContent = user.name || 'No name';
                document.getElementById('user-email').textContent = user.email;
                document.getElementById('user-avatar').src = user.picture || 'https://via.placeholder.com/48';
                
                document.getElementById('session-status').textContent = 'Active session';
            }

            // Show logged out state
            function showLoggedOut() {
                document.getElementById('logged-in').classList.add('hidden');
                document.getElementById('logged-out').classList.remove('hidden');
                document.getElementById('session-status').textContent = 'No session';
                currentSessionToken = null;
                currentUser = null;
            }

            // Get user info
            async function getUserInfo() {
                if (!currentSessionToken) {
                    showResponse({error: true, message: 'No active session'});
                    return;
                }

                try {
                    const response = await fetch(`${API_BASE}/api/user/me`, {
                        headers: {
                            'Authorization': `Bearer ${currentSessionToken}`
                        }
                    });

                    const data = await response.json();
                    showResponse(data);
                } catch (error) {
                    showResponse({error: true, message: error.message});
                }
            }

            // Logout
            function logout() {
                // Sign out from Google
                google.accounts.id.disableAutoSelect();
                
                // Clear local state
                showLoggedOut();
                showResponse({success: true, message: 'Successfully logged out'});
            }

            // Show API response
            function showResponse(data) {
                const container = document.getElementById('response-container');
                const responseEl = document.getElementById('api-response');
                
                responseEl.textContent = JSON.stringify(data, null, 2);
                container.classList.remove('hidden');
            }

            // Clear response
            function clearResponse() {
                document.getElementById('response-container').classList.add('hidden');
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/api/auth/google")
async def google_auth(payload: GoogleAuthRequest):
    """Authenticate user with Google and create session"""
    try:
        print(f"🔍 Received Google token: {payload.google_token[:50]}...")
        
        # Verify Google token
        user_info = await verify_google_token(payload.google_token)
        print(f"✅ Google token verified. User: {user_info.get('email')}")
        
        # Create or get user
        user = await create_or_get_user(user_info)
        print(f"✅ User created/retrieved: {user['id']}")
        
        # Generate session token
        session_token = generate_session_token()
        user_sessions[session_token] = {
            "user_id": user["id"],
            "email": user["email"],
            "name": user["full_name"],
            "picture": user["profile_picture_url"],
            "expires_at": datetime.utcnow() + timedelta(hours=24)
        }
        
        # Store session in database for persistence
        try:
            supabase.table('nota_user_sessions').insert({
                'user_id': user['id'],
                'session_token': session_token,
                'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
                'ip_address': '127.0.0.1',  # You can get this from request
                'user_agent': 'Web App'
            }).execute()
            print(f"✅ Session stored in database")
        except Exception as db_error:
            print(f"⚠️ Failed to store session in DB: {db_error}")
            # Continue anyway - session is in memory
        
        return {
            "success": True,
            "session_token": session_token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user["full_name"],
                "picture": user["profile_picture_url"]
            }
        }
        
    except HTTPException as he:
        print(f"❌ HTTP Exception: {he.detail}")
        raise he
    except Exception as e:
        print(f"❌ Unexpected error in google_auth: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"Authentication error: {str(e)}")

@app.get("/api/user/me")
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information"""
    return {
        "success": True,
        "user": current_user
    }

@app.post("/api/auth/logout")
async def logout(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Logout user and invalidate session"""
    # Remove from in-memory sessions
    for token, session_data in list(user_sessions.items()):
        if session_data.get('user_id') == current_user.get('user_id'):
            del user_sessions[token]
    
    # Remove from database
    supabase.table('nota_user_sessions').delete().eq('user_id', current_user.get('user_id')).execute()
    
    return {"success": True, "message": "Successfully logged out"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.get("/debug/sessions")
async def debug_sessions():
    """Debug endpoint to see active sessions"""
    return {
        "active_sessions": len(user_sessions),
        "sessions": {k: {**v, "expires_at": v["expires_at"].isoformat()} for k, v in user_sessions.items()}
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)