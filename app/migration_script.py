# migration_script.py - Run this ONCE to update existing data

import asyncio
from database_fixed import connect_to_mongo, migrate_existing_repositories, close_mongo_connection

async def run_migration():
    """
    Migration script to add email deduplication fields to existing repositories
    This should be run ONCE after deploying the new code
    """
    print("🚀 Starting migration for email deduplication...")
    
    try:
        # Connect to database
        await connect_to_mongo()
        print("✅ Connected to database")
        
        # Run migration
        updated_count = await migrate_existing_repositories()
        
        if updated_count > 0:
            print(f"✅ Successfully migrated {updated_count} repositories")
            print("📧 Email deduplication is now active for all repositories")
        else:
            print("✅ All repositories already have email deduplication fields")
        
        # Close connection
        await close_mongo_connection()
        print("✅ Migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    # Run the migration
    success = asyncio.run(run_migration())
    
    if success:
        print("\n" + "="*50)
        print("🎉 MIGRATION COMPLETE!")
        print("="*50)
        print("Next steps:")
        print("1. Replace your current scheduler.py with scheduler_fixed.py")
        print("2. Replace your current email_service.py with email_service_fixed.py") 
        print("3. Replace your current database.py with database_fixed.py")
        print("4. Restart your application")
        print("5. Users will now receive only ONE email per commit/batch!")
        print("="*50)
    else:
        print("\n❌ Migration failed. Please check the error messages above.")
