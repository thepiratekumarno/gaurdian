import os
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()

async def create_organization_webhook(org_name: str) -> dict:
    """Create organization-level webhook to catch all repository events"""
    
    access_token = os.getenv("GITHUB_ACCESS_TOKEN")
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    base_url = os.getenv("BASE_URL", "https://secretguardian.onrender.com")
    
    if not all([access_token, webhook_secret, base_url, org_name]):
        return {"error": "Missing required configuration or organization name"}
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    webhook_data = {
        "name": "web",
        "active": True,
        "events": [
            "repository",     # Repository created, deleted, publicized, etc.
            "push",          # Push events to any repository
            "pull_request"   # Optional: Pull request events
        ],
        "config": {
            "url": f"{base_url}/github-webhook",
            "content_type": "json",
            "secret": webhook_secret,
            "insecure_ssl": "0"
        }
    }
    
    url = f"https://api.github.com/orgs/{org_name}/hooks"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=webhook_data)
            
            if response.status_code == 201:
                webhook_info = response.json()
                return {
                    "success": True,
                    "webhook_id": webhook_info["id"],
                    "message": f"Organization webhook created successfully for {org_name}",
                    "webhook_url": webhook_info["url"],
                    "events": webhook_info["events"]
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to create webhook: {response.status_code} - {response.text}"
                }
                
    except Exception as e:
        return {"success": False, "error": str(e)}

async def list_organization_webhooks(org_name: str) -> dict:
    """List existing organization webhooks"""
    
    access_token = os.getenv("GITHUB_ACCESS_TOKEN")
    if not access_token:
        return {"error": "GitHub access token not configured"}
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    url = f"https://api.github.com/orgs/{org_name}/hooks"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                webhooks = response.json()
                return {
                    "success": True,
                    "webhooks": webhooks,
                    "count": len(webhooks)
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to list webhooks: {response.status_code} - {response.text}"
                }
                
    except Exception as e:
        return {"success": False, "error": str(e)}

async def main():
    """Main function to setup organization webhook"""
    
    print("🔧 SecretGuardian Organization Webhook Setup")
    print("=" * 50)
    
    # Check if required environment variables are set
    required_vars = ["GITHUB_ACCESS_TOKEN", "GITHUB_WEBHOOK_SECRET", "BASE_URL"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease update your .env file and try again.")
        return
    
    print("✅ Environment variables configured")
    
    # Get organization name from user
    org_name = input("\nEnter your GitHub organization name: ").strip()
    
    if not org_name:
        print("❌ Organization name is required!")
        return
    
    print(f"\n📋 Setting up webhook for organization: {org_name}")
    
    # First, list existing webhooks
    print("\n🔍 Checking existing webhooks...")
    existing = await list_organization_webhooks(org_name)
    
    if existing.get("success"):
        webhooks = existing.get("webhooks", [])
        if webhooks:
            print(f"📌 Found {len(webhooks)} existing webhook(s):")
            for hook in webhooks:
                webhook_url = hook.get('config', {}).get('url', 'N/A')
                print(f"   - ID: {hook['id']}, URL: {webhook_url}")
                
                # Check if our webhook already exists
                if "secretguardian" in webhook_url.lower() or "github-webhook" in webhook_url:
                    print(f"   ⚠️  SecretGuardian webhook may already exist!")
        else:
            print("📌 No existing webhooks found")
    else:
        print(f"❌ Error checking webhooks: {existing.get('error')}")
        return
    
    # Ask user if they want to proceed
    proceed = input("\n❓ Do you want to create a new organization webhook? (y/n): ").strip().lower()
    
    if proceed != 'y':
        print("⏹️  Setup cancelled")
        return
    
    # Create the webhook
    print("\n🚀 Creating organization webhook...")
    result = await create_organization_webhook(org_name)
    
    if result.get("success"):
        print(f"✅ {result['message']}")
        print(f"📝 Webhook ID: {result['webhook_id']}")
        print(f"🔗 Webhook URL: {result['webhook_url']}")
        print(f"📋 Events: {', '.join(result['events'])}")
        print("\n🎉 Setup complete! Your application will now automatically detect new repositories.")
        print("\n📌 Next steps:")
        print("1. When users create new repositories in this organization, they will be automatically added")
        print("2. Automatic security scans will be triggered")
        print("3. Email notifications will be sent with results")
        print("\n🔧 Test the setup:")
        print("1. Create a new repository in your organization")
        print("2. Check your application logs for webhook events")
        print("3. Verify the repository appears in your dashboard")
        print("4. Confirm you receive email notifications")
    else:
        print(f"❌ Setup failed: {result.get('error')}")
        print("\n🔧 Troubleshooting:")
        print("1. Make sure your GitHub token has 'admin:org_hook' permissions")
        print("2. Verify you are an organization owner")
        print("3. Check that BASE_URL and GITHUB_WEBHOOK_SECRET are configured")
        print("4. Ensure your server is accessible from GitHub")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⏹️  Setup cancelled by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("Please check your configuration and try again.")
