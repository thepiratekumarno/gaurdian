import os
import logging
import secrets
import traceback
from datetime import datetime

from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse  # ← Make sure this is here
from authlib.integrations.starlette_client import OAuth, OAuthError
from dotenv import load_dotenv
import httpx

from . import crud, database

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class OAuthManager:
    def __init__(self):
        self.oauth = OAuth()
        self._register_providers()

    def _register_providers(self):
        base_url = os.getenv("BASE_URL", "http://localhost:8000")

        # GitHub OAuth
        self.oauth.register(
            name="github",
            client_id=os.getenv("GITHUB_CLIENT_ID"),
            client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "user:email,repo"},
            redirect_uri=f"{base_url}/auth/github/callback"
        )

        # Google OAuth
        self.oauth.register(
            name="google",
            client_id=os.getenv("GOOGLE_CLIENT_ID"),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
            redirect_uri=f"{base_url}/auth/google/callback"
        )

    async def github_login(self, request: Request):
        """Initiate GitHub login flow"""
        try:
            state = secrets.token_urlsafe(16)
            request.session["oauth_state"] = state
            request.session["oauth_provider"] = "github"
            return await self.oauth.github.authorize_redirect(
                request,
                f"{os.getenv('BASE_URL')}/auth/github/callback",
                state=state
            )
        except Exception as e:
            logger.error(f"GitHub login failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="GitHub login initialization failed")

    async def github_callback(self, request: Request):
        """Handle GitHub OAuth callback"""
        try:
            logger.info("GitHub callback received")
        
        # Verify state
            query_state = request.query_params.get("state")
            session_state = request.session.get("oauth_state")
            if not query_state or query_state != session_state:
                raise HTTPException(status_code=400, detail="Invalid state parameter")

        # Get access token
            token = await self.oauth.github.authorize_access_token(request)
            if not token or 'access_token' not in token:
                raise HTTPException(status_code=400, detail="Failed to obtain access token")

        # Get user info
            resp = await self.oauth.github.get("user", token=token)
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to fetch user info")
            user_data = resp.json()

        # Get email
            email_resp = await self.oauth.github.get("user/emails", token=token)
            emails = email_resp.json() if email_resp.status_code == 200 else []
            primary_email = next(
                (e["email"] for e in emails if e.get("primary")),
                user_data.get("email")
            )
            if not primary_email:
                primary_email = f"{user_data['login']}@users.noreply.github.com"

        # Store access token for repository access
            request.session["github_access_token"] = token["access_token"]
        
            user_info = {
                "provider": "github",
                "id": str(user_data["id"]),
                "username": user_data["login"],
                "email": primary_email,
                "name": user_data.get("name") or user_data["login"],
                "avatar_url": user_data.get("avatar_url")
            }

        # Store user in session
            request.session["user"] = user_info

        # Store token in database for background polling
            github_token = token["access_token"]
            db = await database.get_database()
            await db.users.update_one(
                {"email": primary_email},
                {
                    "$set": {
                        "github_access_token": github_token,
                        "token_updated_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
            logger.info(f"Stored GitHub token for {primary_email}")

        # Create or update user in database
            await crud.create_or_get_user(
                email=primary_email,
                username=user_info["username"],
                full_name=user_info["name"],
                provider=user_info["provider"],
                provider_id=user_info["id"]
            )

            logger.info(f"GitHub user successfully authenticated: {primary_email}")
            return RedirectResponse(url="/dashboard")

        except HTTPException as e:
            logger.error(f"GitHub auth error: {e.detail}")
            return RedirectResponse(url="/?error=github_auth_failed")
        except OAuthError as e:
            logger.error(f"OAuth error during GitHub callback: {e.error}")
            return RedirectResponse(url="/?error=github_auth_failed")
        except Exception as e:
            logger.error(f"GitHub callback error: {e}", exc_info=True)
            return RedirectResponse(url="/?error=github_auth_failed")


    async def google_login(self, request: Request):
        """Initiate Google login flow"""
        try:
            state = secrets.token_urlsafe(16)
            request.session["oauth_state"] = state
            request.session["oauth_provider"] = "google"
            return await self.oauth.google.authorize_redirect(
                request,
                f"{os.getenv('BASE_URL')}/auth/google/callback",
                state=state
            )
        except Exception as e:
            logger.error(f"Google login failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Google login initialization failed")

    async def google_callback(self, request: Request):
        """Handle Google OAuth callback"""
        try:
            # Verify state
            query_state = request.query_params.get("state")
            session_state = request.session.get("oauth_state")
            if not query_state or query_state != session_state:
                raise HTTPException(status_code=400, detail="Invalid state parameter")

            token = await self.oauth.google.authorize_access_token(request)
            if not token:
                raise HTTPException(status_code=400, detail="Failed to obtain access token")

            user_data = token.get("userinfo")
            if not user_data:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        "https://openidconnect.googleapis.com/v1/userinfo",
                        headers={"Authorization": f"Bearer {token['access_token']}"}
                    )
                    user_data = response.json()
            if not user_data.get("email"):
                raise HTTPException(status_code=400, detail="No email found in user info")

            return {
                "provider": "google",
                "id": user_data["sub"],
                "username": user_data["email"].split("@")[0],
                "email": user_data["email"],
                "name": user_data.get("name") or user_data["email"].split("@")[0],
                "avatar_url": user_data.get("picture")
            }

        except HTTPException as e:
            logger.error(f"Google auth error: {e.detail}")
            raise
        except Exception as e:
            logger.error(f"Google callback exception: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Google authentication failed")


oauth_manager = OAuthManager()


def get_current_user(request: Request):
    """Get current user from session"""
    return request.session.get("user")


def require_auth(request: Request):
    """Require authenticated user"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def logout_user(request: Request):
    """Clear user session"""
    request.session.clear()
    return {"message": "Logged out successfully"}
