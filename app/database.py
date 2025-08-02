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
    """Create database indexes for better performance"""
    try:
        # Users collection indexes
        await db.database.users.create_index("email", unique=True)
        await db.database.users.create_index("username")
        
        # Reports collection indexes
        await db.database.reports.create_index("user_email")
        await db.database.reports.create_index("created_at")
        await db.database.reports.create_index("repository_name")
        
        # Repositories collection indexes
        await db.database.repositories.create_index("user_email")
        await db.database.repositories.create_index("repository_name")
        
        print("Database indexes created successfully!")
        
    except Exception as e:
        print(f"Error creating indexes: {e}")

async def get_database():
    """Get database instance"""
    return db.database