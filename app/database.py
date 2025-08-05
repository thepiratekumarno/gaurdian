
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
    """Create database indexes for better performance - UPDATED FOR EMAIL DEDUPLICATION"""
    try:
        # Users collection indexes
        await db.database.users.create_index("email", unique=True)
        await db.database.users.create_index("username")
        await db.database.users.create_index("github_access_token")  # For scheduler efficiency
        
        # Reports collection indexes
        await db.database.reports.create_index("user_email")
        await db.database.reports.create_index("created_at")
        await db.database.reports.create_index("repository_name")
        
        # Repositories collection indexes - ENHANCED FOR EMAIL DEDUPLICATION
        await db.database.repositories.create_index("user_email")
        await db.database.repositories.create_index("repository_name")
        await db.database.repositories.create_index("last_known_push")  # For commit tracking
        await db.database.repositories.create_index("scan_frozen_until")  # For freeze logic
        await db.database.repositories.create_index("last_emailed_push")  # For email deduplication
        await db.database.repositories.create_index("last_email_sent_at")  # For email timing
        
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
        
        print("Database indexes created successfully with email deduplication support!")
        
    except Exception as e:
        print(f"Error creating indexes: {e}")

async def get_database():
    """Get database instance"""
    return db.database

async def migrate_existing_repositories():
    """
    Migration function to add email deduplication fields to existing repositories
    Run this once after updating your code
    """
    try:
        db_instance = await get_database()
        
        # Add new fields to existing repositories that don't have them
        result = await db_instance.repositories.update_many(
            {
                "$or": [
                    {"last_emailed_push": {"$exists": False}},
                    {"last_email_sent_at": {"$exists": False}},
                    {"email_batch_commits": {"$exists": False}}
                ]
            },
            {
                "$set": {
                    "last_emailed_push": None,
                    "last_email_sent_at": None,
                    "email_batch_commits": []
                }
            }
        )
        
        print(f"✅ Migration completed: Updated {result.modified_count} repositories with email deduplication fields")
        return result.modified_count
        
    except Exception as e:
        print(f"❌ Migration error: {e}")
        return 0
