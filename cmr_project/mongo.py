from pymongo import MongoClient
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MONGO_URI = "mongodb://localhost:27017/"

def init_collections(db):
    """Initialize all required collections with their indexes"""
    try:
        # Create nursing_homes collection if it doesn't exist
        if 'nursing_homes' not in db.list_collection_names():
            db.create_collection('nursing_homes')
            db['nursing_homes'].create_index([("nursing_home_id", 1)], unique=True)
            db['nursing_homes'].create_index([("email", 1)], unique=True)
            logger.info("Created nursing_homes collection with indexes")

        # Create multispeciality_hospitals collection if it doesn't exist
        if 'multispeciality_hospitals' not in db.list_collection_names():
            db.create_collection('multispeciality_hospitals')
            db['multispeciality_hospitals'].create_index([("hospital_id", 1)], unique=True)
            db['multispeciality_hospitals'].create_index([("district", 1)])
            db['multispeciality_hospitals'].create_index([("name", 1)])
            logger.info("Created multispeciality_hospitals collection with indexes")

        return True
    except Exception as e:
        logger.error(f"Error initializing collections: {str(e)}")
        return False

# Initialize MongoDB connection with retry logic
def init_mongodb_connection():
    global mongo_client, db
    try:
        mongo_client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=10000,
            retryWrites=True,
            retryReads=True
        )
        
        # Test the connection
        mongo_client.server_info()
        logger.info("Successfully connected to MongoDB")
        
        # Initialize database and collections
        db = mongo_client['caresync_db']
        if init_collections(db):
            logger.info("Successfully initialized all collections")
            return True
        else:
            logger.error("Failed to initialize collections")
            return False
    except Exception as e:
        logger.error(f"MongoDB Connection Error: {str(e)}")
        mongo_client = None
        db = None
        return False

# Initialize MongoDB connection
if not init_mongodb_connection():
    logger.error("Failed to initialize MongoDB connection")
    mongo_client = None
    db = None
else:
    logger.info("MongoDB connection and initialization successful")
