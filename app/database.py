
import motor.motor_asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

load_dotenv()

class Database:
    client: AsyncIOMotorClient = None
    database = None

db = Database()

async def connect_to_mongo():
    """Create database connection"""
    try:
        # MongoDB Atlas connection
        db.client = AsyncIOMotorClient(
            os.getenv("MONGO_URI"),
            tls=True,
            tlsAllowInvalidCertificates=True
        )
        
        # Test connection
        await db.client.admin.command('ping')
        print("Successfully connected to MongoDB Atlas!")
        
        # Get database
        db.database = db.client.secretguardian_db
        
        # Create indexes for better performance
        await create_indexes()
        
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        # Attempt to create database if it doesn't exist
        db.database = db.client.get_database("secretguardian_db")
        await create_indexes()

async def close_mongo_connection():
    """Close database connection"""
    if db.client:
        db.client.close()

async def create_indexes():
    """Create database indexes for better performance - FINAL VERSION"""
    try:
        # Users collection indexes
        await db.database.users.create_index("email", unique=True)
        await db.database.users.create_index("username")
        await db.database.users.create_index("github_access_token")  # For scheduler efficiency
        
        # Reports collection indexes
        await db.database.reports.create_index("user_email")
        await db.database.reports.create_index("created_at")
        await db.database.reports.create_index("repository_name")
        await db.database.reports.create_index("_id")  # For report URL access
        
        # Repositories collection indexes - FINAL VERSION with new user tracking
        await db.database.repositories.create_index("user_email")
        await db.database.repositories.create_index("repository_name")
        await db.database.repositories.create_index("last_known_push")  # For commit tracking
        await db.database.repositories.create_index("scan_frozen_until")  # For freeze logic
        await db.database.repositories.create_index("last_emailed_push")  # For email deduplication
        await db.database.repositories.create_index("last_email_sent_at")  # For email timing
        
        # New user tracking indexes
        await db.database.repositories.create_index("discovered_for_new_user")  # For new user repo discovery
        await db.database.repositories.create_index("initial_discovery")  # For initial discovery tracking
        
        # ATOMIC LOCKING INDEXES
        await db.database.repositories.create_index("scan_status")  # For scan status queries
        await db.database.repositories.create_index("scan_lock_id")  # For lock ownership
        await db.database.repositories.create_index("scan_lock_expires")  # For expired lock cleanup
        await db.database.repositories.create_index("scan_worker_id")  # For worker identification
        
        # Compound indexes for complex queries
        await db.database.repositories.create_index([
            ("user_email", 1),
            ("is_monitored", 1),
            ("scan_status", 1)
        ])
        
        await db.database.repositories.create_index([
            ("user_email", 1),
            ("last_known_push", 1),
            ("last_emailed_push", 1)
        ])
        
        # Compound index for new user discovery
        await db.database.repositories.create_index([
            ("user_email", 1),
            ("discovered_for_new_user", 1),
            ("initial_discovery", 1)
        ])
        
        # Compound index for atomic lock acquisition
        await db.database.repositories.create_index([
            ("_id", 1),
            ("scan_status", 1),
            ("scan_lock_expires", 1)
        ])
        
        print("Database indexes created successfully with new user tracking support!")
        
    except Exception as e:
        print(f"Error creating indexes: {e}")

async def get_database():
    """Get database instance"""
    return db.database

async def migrate_to_final_version():
    """
    Migration function to add new user tracking fields to existing repositories
    Run this once after updating your code to the final version
    """
    try:
        db_instance = await get_database()
        
        # Add new fields to existing repositories that don't have them
        result = await db_instance.repositories.update_many(
            {
                "$or": [
                    {"last_emailed_push": {"$exists": False}},
                    {"last_email_sent_at": {"$exists": False}},
                    {"email_batch_commits": {"$exists": False}},
                    {"scan_lock_id": {"$exists": False}},
                    {"discovered_for_new_user": {"$exists": False}},
                    {"initial_discovery": {"$exists": False}}
                ]
            },
            {
                "$set": {
                    # Email deduplication fields
                    "last_emailed_push": None,
                    "last_email_sent_at": None,
                    "email_batch_commits": [],
                    
                    # Atomic locking fields  
                    "scan_status": "idle",
                    
                    # New user tracking fields
                    "discovered_for_new_user": False,  # Existing repos are not from new user discovery
                    "initial_discovery": False
                },
                "$unset": {
                    # Remove any stale lock fields from previous versions
                    "scan_lock_id": "",
                    "scan_lock_expires": "",
                    "scan_worker_id": "",
                    "scan_started_at": ""
                }
            }
        )
        
        print(f"✅ Final migration completed: Updated {result.modified_count} repositories with new user tracking")
        return result.modified_count
        
    except Exception as e:
        print(f"❌ Final migration error: {e}")
        return 0

async def cleanup_stale_locks():
    """
    Cleanup function to remove any stale or expired locks
    """
    try:
        from datetime import datetime
        db_instance = await get_database()
        now = datetime.utcnow()
        
        # Remove expired locks
        result = await db_instance.repositories.update_many(
            {
                "$or": [
                    {"scan_lock_expires": {"$lt": now}},  # Expired locks
                    {"scan_lock_expires": {"$exists": False}, "scan_status": "scanning"}  # Stale scanning status
                ]
            },
            {
                "$set": {"scan_status": "idle"},
                "$unset": {
                    "scan_lock_id": "",
                    "scan_lock_expires": "",
                    "scan_worker_id": "",
                    "scan_started_at": ""
                }
            }
        )
        
        if result.modified_count > 0:
            print(f"🧹 Cleaned up {result.modified_count} stale/expired locks")
        
        return result.modified_count
        
    except Exception as e:
        print(f"❌ Lock cleanup error: {e}")
        return 0

# Helper functions for manual scanning (for your existing manual scan feature)
async def get_user_repositories_for_manual_scan(user_email: str):
    """
    Get repositories that can be manually scanned by the user
    """
    try:
        db_instance = await get_database()
        
        # Get all repositories for the user
        repositories = await db_instance.repositories.find({
            "user_email": user_email,
            "is_monitored": True
        }).to_list(None)
        
        return repositories
        
    except Exception as e:
        print(f"❌ Error getting repositories for manual scan: {e}")
        return []

async def mark_repository_as_manually_scanned(repo_id: str):
    """
    Mark a repository as having been manually scanned (clears new user discovery flag)
    """
    try:
        db_instance = await get_database()
        
        result = await db_instance.repositories.update_one(
            {"_id": ObjectId(repo_id)},
            {
                "$set": {
                    "discovered_for_new_user": False,
                    "initial_discovery": False,
                    "last_scan": datetime.utcnow()
                }
            }
        )
        
        return result.modified_count > 0
        
    except Exception as e:
        print(f"❌ Error marking repository as manually scanned: {e}")
        return False
