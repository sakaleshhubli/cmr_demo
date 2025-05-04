from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_cors import CORS
import json
import uuid
import os
from datetime import datetime
import hashlib
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId
import logging
import re
from mongo import db, mongo_client  # Import MongoDB connection from mongo.py

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
app.secret_key = 'caresync_secret_key'  # For session management

# Add this list of Karnataka districts at the top of the file, after the imports
KARNATAKA_DISTRICTS = [
    "Bagalkot", "Ballari", "Belagavi", "Bengaluru Rural", "Bengaluru Urban",
    "Bidar", "Chamarajanagar", "Chikballapur", "Chikkamagaluru", "Chitradurga",
    "Dakshina Kannada", "Davanagere", "Dharwad", "Gadag", "Hassan", "Haveri",
    "Kalaburagi", "Kodagu", "Kolar", "Koppal", "Mandya", "Mysuru", "Raichur",
    "Ramanagara", "Shivamogga", "Tumakuru", "Udupi", "Uttara Kannada", "Vijayapura",
    "Yadgir"
]

# Add this after KARNATAKA_DISTRICTS list and before MongoDB Configuration
healthcare_data = {
    'nursing_homes': [
        {
            'clinic_id': 'NH001',
            'name': 'City Care Nursing Home',
            'location': 'Bengaluru',
            'contact_person': 'Dr. Rajesh Kumar',
            'phone': '9876543210',
            'email': 'citycare@example.com'
        },
        {
            'clinic_id': 'NH002',
            'name': 'Lifeline Nursing Home',
            'location': 'Mysuru',
            'contact_person': 'Dr. Priya Singh',
            'phone': '9876543211',
            'email': 'lifeline@example.com'
        },
        {
            'clinic_id': 'NH003',
            'name': 'Hope Healthcare',
            'location': 'Mangaluru',
            'contact_person': 'Dr. John Matthew',
            'phone': '9876543212',
            'email': 'hope@example.com'
        }
    ],
    'patients': [],
    'ambulance_requests': [],
    'pros': [],
    'multispeciality_hospitals': [],
    'counseling_resources': []
}

# MongoDB Configuration
def init_mongodb():
    """Initialize MongoDB connection and collections"""
    global mongo_client, db
    try:
        MONGO_URI = "mongodb://localhost:27017/"
        logger.info("Attempting to connect to MongoDB...")
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
        db = mongo_client['caresync_db']
        
        # Create collections if they don't exist
        collections = db.list_collection_names()
        
        # Create users collection if it doesn't exist
        if 'users' not in collections:
            db.create_collection('users')
            db['users'].create_index([("email", 1)], unique=True)
            db['users'].create_index([("nursing_home_details.phone", 1)], unique=True)
            logger.info("Created users collection with indexes")
        
        # Create patients collection if it doesn't exist
        if 'patients' not in collections:
            db.create_collection('patients')
            db['patients'].create_index([("patient_id", 1)], unique=True)
            db['patients'].create_index([("nursing_home_id", 1)])
            db['patients'].create_index([("district", 1)])
            logger.info("Created patients collection with indexes")
        
        # Create hospitals collection if it doesn't exist
        if 'multispeciality_hospitals' not in collections:
            db.create_collection('multispeciality_hospitals')
            db['multispeciality_hospitals'].create_index([("hospital_id", 1)], unique=True)
            db['multispeciality_hospitals'].create_index([("district", 1)])
            db['multispeciality_hospitals'].create_index([("name", 1)])
            logger.info("Created hospitals collection with indexes")
        
        logger.info("Successfully connected to MongoDB and initialized collections")
        return True
        
    except Exception as e:
        logger.error(f"Error connecting to MongoDB: {str(e)}", exc_info=True)
        mongo_client = None
        db = None
        return False

# Initialize MongoDB connection
if not init_mongodb():
    logger.error("Failed to initialize MongoDB connection")
    # Don't raise the exception, let the app start and handle DB errors gracefully

# Function to get nursing home-specific collection
def get_nursing_home_collection(nursing_home_id):
    try:
        if not mongo_client:
            logger.error("MongoDB client is not initialized")
            raise Exception("MongoDB connection not available")
        return db[f'nursing_home_{nursing_home_id}_patients']
    except Exception as e:
        logger.error(f"Error getting nursing home collection: {str(e)}")
        raise Exception("Failed to access database")

# Function to initialize nursing home collection if it doesn't exist
def init_nursing_home_collection(nursing_home_id):
    try:
        if not mongo_client:
            logger.error("MongoDB client is not initialized")
            raise Exception("MongoDB connection not available")
        collection = get_nursing_home_collection(nursing_home_id)
        if not collection.find_one():
            collection.create_index([("patient_id", 1)], unique=True)
        return collection
    except Exception as e:
        logger.error(f"Error initializing nursing home collection: {str(e)}")
        raise Exception("Failed to initialize database")

# Function to get hospitals collection
def get_hospitals_collection():
    try:
        if not mongo_client:
            logger.error("MongoDB client is not initialized")
            raise Exception("MongoDB connection not available")
        return db['multispeciality_hospitals']
    except Exception as e:
        logger.error(f"Error getting hospitals collection: {str(e)}")
        raise Exception("Failed to access database")

# Function to migrate hospitals to MongoDB
def migrate_hospitals_to_mongodb():
    try:
        hospitals_collection = get_hospitals_collection()
        
        # Check if collection is empty
        if hospitals_collection.count_documents({}) == 0:
            logger.info(f"Migrating {len(healthcare_data['multispeciality_hospitals'])} hospitals to MongoDB")
            
            # Insert hospitals from healthcare_data
            for hospital in healthcare_data['multispeciality_hospitals']:
                try:
                    # Convert boolean fields to proper boolean values
                    hospital['ambulance_services'] = bool(hospital['ambulance_services'])
                    hospital['mental_health_support'] = bool(hospital['mental_health_support'])
                    hospital['financial_assistance'] = bool(hospital['financial_assistance'])
                    
                    # Insert hospital document
                    hospitals_collection.insert_one(hospital)
                    logger.info(f"Successfully migrated hospital: {hospital['name']}")
                except Exception as e:
                    logger.error(f"Error migrating hospital {hospital['name']}: {str(e)}")
                    continue
        
        logger.info("Hospital data migration to MongoDB completed")
        return True
    except Exception as e:
        logger.error(f"Error in migrate_hospitals_to_mongodb: {str(e)}")
        return False

# Function to initialize nursing home credentials
def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def init_nursing_home_credentials():
    """Initialize nursing home credentials in the database"""
    try:
        conn = sqlite3.connect('caresync.db')
        c = conn.cursor()
        
        for home in healthcare_data['nursing_homes']:
            # Check if nursing home exists in database
            c.execute("SELECT * FROM nursing_homes WHERE clinic_id = ?", (home['clinic_id'],))
            if not c.fetchone():
                # Insert nursing home into database
                c.execute("""
                    INSERT INTO nursing_homes (clinic_id, name, location, contact_person, phone, email)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    home['clinic_id'],
                    home['name'],
                    home['location'],
                    home['contact_person'],
                    home['phone'],
                    home['email']
                ))
                
                # Create default username and password
                username = f"clinic_{home['clinic_id'].lower()}"
                password = f"{home['clinic_id']}123"
                
                # Insert user credentials
                c.execute("""
                    INSERT INTO users (username, password, role, entity_id)
                    VALUES (?, ?, ?, ?)
                """, (
                    username,
                    hash_password(password),
                    'nursing_home',
                    home['clinic_id']
                ))
        
        conn.commit()
        conn.close()
        logger.info("Nursing home credentials initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing nursing home credentials: {str(e)}")
        raise

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('nursing_home_login'))
        return f(*args, **kwargs)
    return decorated_function

# Role-based access control decorator
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login to access this page.', 'error')
                return redirect(url_for('nursing_home_login'))
            if session.get('role') not in roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('nursing_home_login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# MongoDB connection check decorator
def mongodb_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not mongo_client:
            logger.error("MongoDB connection is not available")
            flash('Database connection error. Please try again later.', 'error')
            session.clear()  # Clear session on connection error
            return redirect(url_for('nursing_home_login'))
        try:
            # Test the connection
            mongo_client.server_info()
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"MongoDB connection error: {str(e)}")
            flash('Database connection error. Please try again later.', 'error')
            session.clear()  # Clear session on connection error
            return redirect(url_for('nursing_home_login'))
    return decorated_function

@app.route('/nursing-home/login', methods=['GET', 'POST'])
@mongodb_required
def nursing_home_login():
    if request.method == 'POST':
        login_id = request.form.get('login_id')  # This can be email or phone
        password = request.form.get('password')
        
        if not login_id or not password:
            flash('Please enter both login ID and password', 'error')
            return render_template('nursing_home_login.html')
        
        try:
            # Try to find user by email or phone
            user = db.users.find_one({
                '$or': [
                    {'email': login_id},
                    {'nursing_home_details.phone': login_id}
                ]
            })
            
            if not user:
                flash('No account found with this email or phone number', 'error')
                return render_template('nursing_home_login.html')
            
            if user['password'] != hash_password(password):
                flash('Invalid password', 'error')
                return render_template('nursing_home_login.html')
            
            # Set session data
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            session['entity_id'] = user['entity_id']
            
            # Initialize session data
            try:
                init_session_data()
            except Exception as e:
                logger.error(f"Error initializing session data: {str(e)}")
                session.clear()
                flash('Error initializing session. Please try again.', 'error')
                return render_template('nursing_home_login.html')
            
            flash('Login successful!', 'success')
            return redirect(url_for('nursing_home_dashboard'))
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('nursing_home_login.html')

@app.route('/nursing-home/logout')
def nursing_home_logout():
    # Clear all session data
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('nursing_home_login'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html', 
                         hospitals=healthcare_data['multispeciality_hospitals'],
                         nursing_homes=healthcare_data['nursing_homes'])

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        return jsonify({"status": "success", "message": "Thank you for your message!"})
    return render_template('contact.html', 
                         hospitals=healthcare_data['multispeciality_hospitals'],
                         counseling=healthcare_data['counseling_resources'])

@app.route('/add-patient', methods=['GET', 'POST'])
@login_required
@role_required(['nursing_home'])
@mongodb_required
def add_patient():
    if request.method == 'POST':
        try:
            # Get form data
            patient_data = {
                'patient_id': f"P{str(uuid.uuid4())[:8]}",
                'name': request.form.get('name'),
                'age': int(request.form.get('age')),
                'gender': request.form.get('gender'),
                'address': request.form.get('address'),
                'phone': request.form.get('phone'),
                'medical_history': request.form.get('medical_history'),
                'current_condition': request.form.get('current_condition'),
                'admitted_by': session.get('entity_id'),
                'admission_date': datetime.utcnow(),
                'status': 'active'
            }
            
            # Insert patient into MongoDB
            result = db.patients.insert_one(patient_data)
            
            if result.inserted_id:
                flash('Patient added successfully!', 'success')
                return redirect(url_for('nursing_home_dashboard'))
            else:
                flash('Failed to add patient. Please try again.', 'error')
                
        except Exception as e:
            logger.error(f"Error adding patient: {str(e)}")
            flash('An error occurred while adding the patient. Please try again.', 'error')
    
    return render_template('add_patient.html')

@app.route('/patient/<patient_id>')
@login_required
def patient_details(patient_id):
    try:
        # Find patient in MongoDB
        patient = db.patients.find_one({'patient_id': patient_id})
        
        if not patient:
            flash('Patient not found', 'error')
            return redirect(url_for('nursing_home_dashboard'))
        
        # Convert ObjectId to string for JSON serialization
        patient['_id'] = str(patient['_id'])
        
        # Get nursing home details if available
        nursing_home = None
        if patient.get('admitted_by'):
            nursing_home = db.nursing_homes.find_one({'nursing_home_id': patient['admitted_by']})
            if nursing_home:
                nursing_home['_id'] = str(nursing_home['_id'])
        
        return render_template('patient_details.html', 
                             patient=patient,
                             nursing_home=nursing_home)
                             
    except Exception as e:
        logger.error(f"Error viewing patient details: {str(e)}")
        flash('An error occurred while viewing patient details', 'error')
        return redirect(url_for('nursing_home_dashboard'))

@app.route('/patient/<patient_id>/delete', methods=['POST'])
@login_required
@role_required(['nursing_home', 'admin'])
def delete_patient(patient_id):
    try:
        # Find and delete patient from MongoDB
        result = db.patients.delete_one({'patient_id': patient_id})
        
        if result.deleted_count > 0:
            flash('Patient deleted successfully', 'success')
        else:
            flash('Patient not found', 'error')
            
    except Exception as e:
        logger.error(f"Error deleting patient: {str(e)}")
        flash('An error occurred while deleting the patient', 'error')
        
    return redirect(url_for('nursing_home_dashboard'))

@app.route('/patient/<patient_id>/request-ambulance', methods=['POST'])
@login_required
@role_required(['nursing_home', 'admin'])
def request_ambulance(patient_id):
    # Find the patient in the session
    patients = session.get('patients', [])
    patient = next((p for p in patients if p['patient_id'] == patient_id), None)
    
    if not patient:
        return jsonify({"status": "error", "message": "Patient not found"}), 404
    
    # Check if user has permission to request ambulance for this patient
    if session['user']['role'] == 'nursing_home' and patient.get('referred_by') != session['user']['entity_id']:
        return jsonify({"status": "error", "message": "You do not have permission to request ambulance for this patient"}), 403
    
    # Get the request data
    data = request.json
    pickup_location = data.get('pickup_location')
    drop_location = data.get('drop_location')
    
    if not pickup_location or not drop_location:
        return jsonify({"status": "error", "message": "Missing required fields"}), 400
    
    # Create a new ambulance request
    ambulance_request = {
        'request_id': str(uuid.uuid4())[:8],
        'patient_id': patient_id,
        'pickup_location': pickup_location,
        'drop_location': drop_location,
        'status': 'Pending',
        'created_at': datetime.now().isoformat()
    }
    
    # Add the request to the session
    ambulance_requests = session.get('ambulance_requests', [])
    ambulance_requests.append(ambulance_request)
    session['ambulance_requests'] = ambulance_requests
    
    # Update the patient status
    patient['current_status'] = 'In Transit'
    session['patients'] = patients
    
    return jsonify({"status": "success", "message": "Ambulance requested successfully"})

@app.route('/api/patients')
@login_required
def get_patients():
    # Filter patients based on user role
    if session['user']['role'] == 'nursing_home':
        patients = [p for p in session.get('patients', []) 
                   if p.get('referred_by') == session['user']['entity_id']]
    else:
        patients = session.get('patients', [])
    
    return jsonify(patients)

@app.route('/api/hospitals')
@login_required
def get_hospitals():
    try:
        hospitals_collection = get_hospitals_collection()
        hospitals = list(hospitals_collection.find())
        
        # Convert ObjectId to string for JSON serialization
        for hospital in hospitals:
            hospital['_id'] = str(hospital['_id'])
        
        logger.info(f"API: Loaded {len(hospitals)} hospitals from MongoDB")
        return jsonify(hospitals)
        
    except Exception as e:
        logger.error(f"API: Error loading hospitals from MongoDB: {str(e)}")
        return jsonify({"error": "Failed to load hospitals"}), 500

@app.route('/api/ambulance-requests')
@login_required
def get_ambulance_requests():
    # Filter ambulance requests based on user role
    if session['user']['role'] == 'nursing_home':
        requests = [r for r in session.get('ambulance_requests', []) 
                   if r.get('requested_by') == session['user']['entity_id']]
    else:
        requests = session.get('ambulance_requests', [])
    
    return jsonify(requests)

@app.route('/api/pros')
@login_required
def get_pros():
    return jsonify(healthcare_data.get('pros', []))

@app.route('/patient/<patient_id>/assign-pro', methods=['POST'])
@login_required
@role_required(['nursing_home', 'admin'])
def assign_pro(patient_id):
    # Find the patient in the session
    patients = session.get('patients', [])
    patient = next((p for p in patients if p['patient_id'] == patient_id), None)
    
    if not patient:
        return jsonify({"status": "error", "message": "Patient not found"}), 404
    
    # Check if user has permission to assign PRO for this patient
    if session['user']['role'] == 'nursing_home' and patient.get('referred_by') != session['user']['entity_id']:
        return jsonify({"status": "error", "message": "You do not have permission to assign PRO for this patient"}), 403
    
    # Get the request data
    data = request.json
    pro_id = data.get('pro_id')
    
    if not pro_id:
        return jsonify({"status": "error", "message": "Missing PRO ID"}), 400
    
    # Find the PRO
    pros = healthcare_data.get('pros', [])
    pro = next((p for p in pros if p['pro_id'] == pro_id), None)
    
    if not pro:
        return jsonify({"status": "error", "message": "PRO not found"}), 404
    
    # Update the patient with the assigned PRO
    patient['assigned_pro_id'] = pro_id
    session['patients'] = patients
    
    # Update the PRO's assigned patients
    if 'patients_assigned' not in pro:
        pro['patients_assigned'] = []
    
    if patient_id not in pro['patients_assigned']:
        pro['patients_assigned'].append(patient_id)
    
    return jsonify({"status": "success", "message": "PRO assigned successfully"})

@app.route('/hospitals')
@login_required
def list_hospitals():
    """View all hospitals with option to edit"""
    try:
        hospitals_collection = get_hospitals_collection()
        hospitals = list(hospitals_collection.find())
        
        logger.info(f"Loaded {len(hospitals)} hospitals from MongoDB")
        return render_template('hospitals.html', hospitals=hospitals)
        
    except Exception as e:
        logger.error(f"Error loading hospitals from MongoDB: {str(e)}")
        flash('Error loading hospitals. Please try again later.', 'error')
        return redirect(url_for('home'))

@app.route('/hospital/<hospital_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def edit_hospital(hospital_id):
    try:
        hospitals_collection = get_hospitals_collection()
        hospital = hospitals_collection.find_one({'hospital_id': hospital_id})
        
        if not hospital:
            flash('Hospital not found!', 'error')
            return redirect(url_for('list_hospitals'))
        
        if request.method == 'POST':
            # Update hospital data
            update_data = {
                "name": request.form.get('name'),
                "location": request.form.get('location'),
                "contact_number": request.form.get('contact_number'),
                "total_beds": int(request.form.get('total_beds')),
                "available_beds": int(request.form.get('available_beds')),
                "icu_beds": {
                    "total": int(request.form.get('icu_total')),
                    "available": int(request.form.get('icu_available'))
                },
                "specialties": [s.strip() for s in request.form.get('specialties').split(',')],
                "ambulance_services": 'ambulance_services' in request.form,
                "mental_health_support": 'mental_health_support' in request.form,
                "financial_assistance": 'financial_assistance' in request.form
            }
            
            # Update the hospital document
            result = hospitals_collection.update_one(
                {'hospital_id': hospital_id},
                {'$set': update_data}
            )
            
            if result.modified_count > 0:
                flash('Hospital updated successfully!', 'success')
            else:
                flash('No changes were made to the hospital data.', 'info')
            
            return redirect(url_for('list_hospitals'))
        
        return render_template('edit_hospital.html', hospital=hospital)
        
    except Exception as e:
        logger.error(f"Error editing hospital: {str(e)}")
        flash('Error editing hospital. Please try again later.', 'error')
        return redirect(url_for('list_hospitals'))

@app.route('/hospital/<hospital_id>/delete', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_hospital(hospital_id):
    try:
        hospitals_collection = get_hospitals_collection()
        result = hospitals_collection.delete_one({'hospital_id': hospital_id})
        
        if result.deleted_count > 0:
            flash('Hospital deleted successfully!', 'success')
        else:
            flash('Hospital not found!', 'error')
        
        return redirect(url_for('list_hospitals'))
        
    except Exception as e:
        logger.error(f"Error deleting hospital: {str(e)}")
        flash('Error deleting hospital. Please try again later.', 'error')
        return redirect(url_for('list_hospitals'))

@app.route('/nursing-home/dashboard')
@login_required
@role_required(['nursing_home'])
@mongodb_required
def nursing_home_dashboard():
    try:
        # Get the nursing home's ID
        nursing_home_id = session.get('entity_id')
        if not nursing_home_id:
            logger.error("No entity_id found in session")
            session.clear()
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('nursing_home_login'))
        
        logger.info(f"Fetching dashboard data for nursing home: {nursing_home_id}")
        
        try:
            # Get nursing home details
            nursing_home = db['nursing_homes'].find_one(
                {"nursing_home_id": nursing_home_id},
                {'_id': 0, 'password': 0}  # Exclude sensitive fields
            )
            if not nursing_home:
                raise Exception("Nursing home not found in database")
            
            # Get all patients admitted by this nursing home
            patients = list(db['patients'].find(
                {"admitted_by": nursing_home_id},  # Filter by admitting nursing home
                {
                    'patient_id': 1,
                    'name': 1,
                    'age': 1,
                    'gender': 1,
                    'contact_number': 1,
                    'address': 1,
                    'district': 1,
                    'medical_history': 1,
                    'current_status': 1,
                    'assigned_hospital_id': 1,
                    'nursing_home_id': 1,
                    'admitted_by': 1,
                    'admission_date': 1,
                    '_id': 0
                }
            ).sort('admission_date', -1))  # Sort by admission date
            logger.info(f"Successfully fetched {len(patients)} patients")
            
            # Get all hospitals
            hospitals = list(db['multispeciality_hospitals'].find({}, {'_id': 0}))
            logger.info(f"Successfully fetched {len(hospitals)} hospitals")
            
            # Update session data
            session['patients'] = patients
            session['hospitals'] = hospitals
            session.modified = True
            
            return render_template('nursing_home_dashboard.html',
                                patients=patients,
                                hospitals=hospitals,
                                nursing_home=nursing_home)
            
        except Exception as e:
            logger.error(f"Error accessing MongoDB collections: {str(e)}")
            session.clear()
            flash('Database error. Please login again.', 'error')
            return redirect(url_for('nursing_home_login'))
        
    except Exception as e:
        logger.error(f"Error in dashboard: {str(e)}")
        session.clear()
        flash('An error occurred. Please login again.', 'error')
        return redirect(url_for('nursing_home_login'))

@app.route('/admin/dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    return render_template('admin_dashboard.html',
                         patients=session.get('patients', []),
                         hospitals=healthcare_data['multispeciality_hospitals'],
                         nursing_homes=healthcare_data['nursing_homes'])

@app.route('/signup', methods=['GET', 'POST'])
@mongodb_required
def signup():
    if request.method == 'POST':
        try:
            # Get all form fields
            name = request.form.get('name')
            location = request.form.get('location')
            contact_person = request.form.get('contact_person')
            phone = request.form.get('phone')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validate required fields
            if not all([name, location, contact_person, phone, email, password, confirm_password]):
                flash('Please fill in all fields', 'error')
                return render_template('signup.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('signup.html')
            
            # Check if email already exists
            existing_user = db.users.find_one({'email': email})
            
            if existing_user:
                flash('Email already exists', 'error')
                return render_template('signup.html')
            
            # Check if phone number already exists
            existing_phone = db.users.find_one({'nursing_home_details.phone': phone})
            
            if existing_phone:
                flash('Phone number already registered', 'error')
                return render_template('signup.html')
            
            # Generate nursing home ID
            nursing_home_id = f"NH{str(uuid.uuid4())[:8]}"
            
            # Create new user document
            user_doc = {
                'username': name,  # Using nursing home name as username
                'password': hash_password(password),
                'email': email,
                'role': 'nursing_home',
                'entity_id': nursing_home_id,
                'created_at': datetime.utcnow(),
                'nursing_home_details': {
                    'name': name,
                    'location': location,
                    'contact_person': contact_person,
                    'phone': phone
                }
            }
            
            # Insert user into MongoDB
            result = db.users.insert_one(user_doc)
            
            if result.inserted_id:
                # Initialize nursing home collection
                init_nursing_home_collection(nursing_home_id)
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('nursing_home_login'))
            else:
                flash('Registration failed. Please try again.', 'error')
                
        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('signup.html')

def migrate_hospital_data():
    """Migrate hospital data from JSON to database"""
    try:
        conn = sqlite3.connect('caresync.db')
        c = conn.cursor()
        
        # Check if hospitals table is empty
        c.execute('SELECT COUNT(*) FROM hospitals')
        if c.fetchone()[0] == 0:
            logger.info(f"Migrating {len(healthcare_data['multispeciality_hospitals'])} hospitals to database")
            # Insert hospitals from healthcare_data
            for hospital in healthcare_data['multispeciality_hospitals']:
                try:
                    c.execute('''
                        INSERT INTO hospitals (
                            hospital_id, name, location, contact_number,
                            total_beds, available_beds, icu_total, icu_available,
                            specialties, ambulance_services, mental_health_support,
                            financial_assistance
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        hospital['hospital_id'],
                        hospital['name'],
                        hospital['location'],
                        hospital['contact_number'],
                        hospital['total_beds'],
                        hospital['available_beds'],
                        hospital['icu_beds']['total'],
                        hospital['icu_beds']['available'],
                        ','.join(hospital['specialties']),
                        hospital['ambulance_services'],
                        hospital['mental_health_support'],
                        hospital['financial_assistance']
                    ))
                    logger.info(f"Successfully migrated hospital: {hospital['name']}")
                except Exception as e:
                    logger.error(f"Error migrating hospital {hospital['name']}: {str(e)}")
                    continue
        
        conn.commit()
        conn.close()
        logger.info("Hospital data migration completed")
        return True
    except Exception as e:
        logger.error(f"Error in migrate_hospital_data: {str(e)}")
        return False

@app.route('/test-db')
def test_db():
    """Test MongoDB connection and database setup"""
    try:
        if not mongo_client:
            return jsonify({"status": "error", "message": "MongoDB client not initialized"})
        
        # Test the connection
        mongo_client.server_info()
        
        # Get collections
        collections = db.list_collection_names()
        
        # Check if nursing_homes collection exists
        if 'nursing_homes' not in collections:
            db.create_collection('nursing_homes')
            db['nursing_homes'].create_index([("nursing_home_id", 1)], unique=True)
            db['nursing_homes'].create_index([("email", 1)], unique=True)
        
        # Try to insert and read a test document
        test_collection = db['nursing_homes']
        test_doc = {
            "nursing_home_id": "TEST001",
            "name": "Test Nursing Home",
            "email": "test@example.com",
            "test": True
        }
        
        # Insert test document
        result = test_collection.insert_one(test_doc)
        
        # Read it back
        found = test_collection.find_one({"nursing_home_id": "TEST001"})
        
        # Clean up
        test_collection.delete_one({"nursing_home_id": "TEST001"})
        
        return jsonify({
            "status": "success",
            "message": "MongoDB connection and operations successful",
            "collections": collections,
            "test_document": found
        })
    except Exception as e:
        logger.error(f"Database test error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/patient/<patient_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required(['nursing_home', 'admin'])
def edit_patient(patient_id):
    try:
        # Get the nursing home ID from session
        nursing_home_id = session.get('entity_id')
        
        # Get nursing home-specific collection
        nursing_home_collection = get_nursing_home_collection(nursing_home_id)
        
        # Find patient in the nursing home's collection
        patient = nursing_home_collection.find_one({'patient_id': patient_id})
        
        if not patient:
            flash('Patient not found!', 'error')
            return redirect(url_for('nursing_home_dashboard'))
        
        # Check if user has permission to edit this patient
        if session.get('role') == 'nursing_home' and patient.get('referred_by') != nursing_home_id:
            flash('You do not have permission to edit this patient', 'error')
            return redirect(url_for('nursing_home_dashboard'))
        
        if request.method == 'POST':
            try:
                # Update patient details
                update_data = {
                    'name': request.form['name'],
                    'age': int(request.form['age']),
                    'gender': request.form['gender'],
                    'contact_number': request.form['contact_number'],
                    'address': request.form['address'],
                    'medical_history': [condition.strip() for condition in request.form['medical_history'].split(',')],
                    'current_status': request.form['current_status']
                }
                
                # Update the patient document
                result = nursing_home_collection.update_one(
                    {'patient_id': patient_id},
                    {'$set': update_data}
                )
                
                if result.modified_count > 0:
                    flash('Patient details updated successfully', 'success')
                else:
                    flash('No changes were made to the patient details', 'info')
                
                return redirect(url_for('patient_details', patient_id=patient_id))
                
            except Exception as e:
                flash(f'Error updating patient: {str(e)}', 'error')
                return redirect(url_for('patient_details', patient_id=patient_id))
        
        # For GET request, render the patient details page
        hospital = None
        if patient.get('assigned_hospital_id'):
            hospital = next((h for h in healthcare_data['multispeciality_hospitals'] 
                           if h['hospital_id'] == patient['assigned_hospital_id']), None)
        
        return render_template('patient_details.html', 
                             patient=patient,
                             hospital=hospital)
                             
    except Exception as e:
        flash('An error occurred while processing your request.', 'error')
        print(f"Error in edit_patient: {str(e)}")
        return redirect(url_for('nursing_home_dashboard'))

def clear_hospitals_collection():
    """Clear all hospitals from the MongoDB collection"""
    try:
        hospitals_collection = get_hospitals_collection()
        result = hospitals_collection.delete_many({})
        logger.info(f"Cleared {result.deleted_count} hospitals from the collection")
        return True
    except Exception as e:
        logger.error(f"Error clearing hospitals collection: {str(e)}")
        return False

# Clear hospitals collection when the app starts
clear_hospitals_collection()

def add_karnataka_hospitals():
    """Add real multispeciality hospitals across all Karnataka districts to MongoDB"""
    try:
        hospitals_collection = get_hospitals_collection()
        
        # List of hospitals with their details
        hospitals = [
            # Bengaluru Urban (10 hospitals)
            {
                "hospital_id": "HBL001",
                "name": "Manipal Hospital",
                "location": "Old Airport Road, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-25024444",
                "total_beds": 600,
                "available_beds": 120,
                "icu_beds": 50,
                "specialties": ["Cardiology", "Neurology", "Oncology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL002",
                "name": "Fortis Hospital",
                "location": "Bannerghatta Road, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-66214444",
                "total_beds": 450,
                "available_beds": 90,
                "icu_beds": 40,
                "specialties": ["Cardiology", "Neurology", "Gastroenterology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL003",
                "name": "Narayana Health City",
                "location": "Hosur Road, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-67506750",
                "total_beds": 500,
                "available_beds": 100,
                "icu_beds": 45,
                "specialties": ["Cardiology", "Neurology", "Oncology", "Pediatrics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL004",
                "name": "Apollo Hospital",
                "location": "Bannerghatta Main Road, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-26304050",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["Cardiology", "Neurology", "Oncology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL005",
                "name": "Columbia Asia Hospital",
                "location": "Hebbal, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-61654444",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["Cardiology", "Neurology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL006",
                "name": "Sakra World Hospital",
                "location": "Marathahalli, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-49694969",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["Cardiology", "Neurology", "Oncology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL007",
                "name": "Mazumdar Shaw Medical Center",
                "location": "Bommasandra, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-71222222",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["Oncology", "Cardiology", "Neurology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL008",
                "name": "BGS Gleneagles Global Hospital",
                "location": "Kengeri, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-26433333",
                "total_beds": 450,
                "available_beds": 90,
                "icu_beds": 40,
                "specialties": ["Cardiology", "Neurology", "Orthopedics", "Gastroenterology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL009",
                "name": "Sparsh Hospital",
                "location": "Yeshwanthpur, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-22277999",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["Orthopedics", "Cardiology", "Neurology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBL010",
                "name": "HOSMAT Hospital",
                "location": "Magrath Road, Bengaluru",
                "district": "Bengaluru Urban",
                "contact_number": "080-25593796",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["Orthopedics", "Sports Medicine", "Neurology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            # Mysuru (8 hospitals)
            {
                "hospital_id": "HMY001",
                "name": "Columbia Asia Hospital",
                "location": "Vijayanagar, Mysuru",
                "district": "Mysuru",
                "contact_number": "0821-3989898",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["Cardiology", "Neurology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HMY002",
                "name": "JSS Hospital",
                "location": "Bannimantap, Mysuru",
                "district": "Mysuru",
                "contact_number": "0821-2548383",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["Cardiology", "Neurology", "General Medicine"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HMY003",
                "name": "K.R. Hospital",
                "location": "Krishnaraja Boulevard, Mysuru",
                "district": "Mysuru",
                "contact_number": "0821-2423000",
                "total_beds": 500,
                "available_beds": 100,
                "icu_beds": 45,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HMY004",
                "name": "Apollo BGS Hospital",
                "location": "Adichunchanagiri Road, Mysuru",
                "district": "Mysuru",
                "contact_number": "0821-2444444",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["Cardiology", "Neurology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HMY005",
                "name": "Mysore Medical College Hospital",
                "location": "Irwin Road, Mysuru",
                "district": "Mysuru",
                "contact_number": "0821-2423000",
                "total_beds": 450,
                "available_beds": 90,
                "icu_beds": 40,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HMY006",
                "name": "Narayana Multispeciality Hospital",
                "location": "Hootagalli, Mysuru",
                "district": "Mysuru",
                "contact_number": "0821-7107107",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["Cardiology", "Neurology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HMY007",
                "name": "Sparsh Hospital",
                "location": "Hunsur Road, Mysuru",
                "district": "Mysuru",
                "contact_number": "0821-7107107",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["Orthopedics", "Cardiology", "Neurology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HMY008",
                "name": "Kamakshi Hospital",
                "location": "Kuvempunagar, Mysuru",
                "district": "Mysuru",
                "contact_number": "0821-2544444",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            # Dakshina Kannada (Mangaluru) (8 hospitals)
            {
                "hospital_id": "HDK001",
                "name": "KMC Hospital",
                "location": "Attavar, Mangaluru",
                "district": "Dakshina Kannada",
                "contact_number": "0824-2444444",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["Cardiology", "Neurology", "Pediatrics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },

            {
                "hospital_id": "HDK002",
                "name": "A.J. Hospital",
                "location": "Kuntikana, Mangaluru",
                "district": "Dakshina Kannada",
                "contact_number": "0824-2225533",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["Cardiology", "Neurology", "General Medicine"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            {
                "hospital_id": "HDK003",
                "name": "Unity Health Complex",
                "location": "Kadri, Mangaluru",
                "district": "Dakshina Kannada",
                "contact_number": "0824-2444444",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDK004",
                "name": "Mangala Hospital",
                "location": "Kankanady, Mangaluru",
                "district": "Dakshina Kannada",
                "contact_number": "0824-2444444",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["Cardiology", "Neurology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDK005",
                "name": "Father Muller Medical College Hospital",
                "location": "Kankanady, Mangaluru",
                "district": "Dakshina Kannada",
                "contact_number": "0824-2238338",
                "total_beds": 500,
                "available_beds": 100,
                "icu_beds": 45,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDK006",
                "name": "Wenlock District Hospital",
                "location": "Hampankatta, Mangaluru",
                "district": "Dakshina Kannada",
                "contact_number": "0824-2220000",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDK007",
                "name": "Highland Hospital",
                "location": "Kadri, Mangaluru",
                "district": "Dakshina Kannada",
                "contact_number": "0824-2444444",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDK008",
                "name": "City Hospital",
                "location": "Hampankatta, Mangaluru",
                "district": "Dakshina Kannada",
                "contact_number": "0824-2444444",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            # Dharwad (Hubballi) (7 hospitals)
            {
                "hospital_id": "HDW001",
                "name": "SDM Hospital",
                "location": "Sattur, Hubballi",
                "district": "Dharwad",
                "contact_number": "0836-2464444",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["Cardiology", "Neurology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDW002",
                "name": "KLES Hospital",
                "location": "JNMC Campus, Hubballi",
                "district": "Dharwad",
                "contact_number": "0836-2444444",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["Cardiology", "Neurology", "General Medicine"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDW003",
                "name": "Karnataka Institute of Medical Sciences",
                "location": "Hubballi",
                "district": "Dharwad",
                "contact_number": "0836-2444444",
                "total_beds": 500,
                "available_beds": 100,
                "icu_beds": 45,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDW004",
                "name": "Sushruta Hospital",
                "location": "Hubballi",
                "district": "Dharwad",
                "contact_number": "0836-2444444",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDW005",
                "name": "Sangameshwar Hospital",
                "location": "Hubballi",
                "district": "Dharwad",
                "contact_number": "0836-2444444",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDW006",
                "name": "Karnataka Hospital",
                "location": "Hubballi",
                "district": "Dharwad",
                "contact_number": "0836-2444444",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HDW007",
                "name": "Sushruta Hospital",
                "location": "Hubballi",
                "district": "Dharwad",
                "contact_number": "0836-2444444",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            # Belagavi (8 hospitals)
            {
                "hospital_id": "HBLG001",
                "name": "KLE Hospital",
                "location": "JNMC Campus, Belagavi",
                "district": "Belagavi",
                "contact_number": "0831-2473777",
                "total_beds": 500,
                "available_beds": 100,
                "icu_beds": 45,
                "specialties": ["Cardiology", "Neurology", "Oncology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBLG002",
                "name": "Belgaum Institute of Medical Sciences",
                "location": "Belagavi",
                "district": "Belagavi",
                "contact_number": "0831-2473777",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["Cardiology", "Neurology", "General Medicine"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBLG003",
                "name": "Sushruta Hospital",
                "location": "Belagavi",
                "district": "Belagavi",
                "contact_number": "0831-2473777",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBLG004",
                "name": "Karnataka Institute of Medical Sciences",
                "location": "Belagavi",
                "district": "Belagavi",
                "contact_number": "0831-2473777",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBLG005",
                "name": "Sangameshwar Hospital",
                "location": "Belagavi",
                "district": "Belagavi",
                "contact_number": "0831-2473777",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBLG006",
                "name": "Karnataka Hospital",
                "location": "Belagavi",
                "district": "Belagavi",
                "contact_number": "0831-2473777",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBLG007",
                "name": "Sushruta Hospital",
                "location": "Belagavi",
                "district": "Belagavi",
                "contact_number": "0831-2473777",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HBLG008",
                "name": "Karnataka Institute of Medical Sciences",
                "location": "Belagavi",
                "district": "Belagavi",
                "contact_number": "0831-2473777",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            # Kalaburagi (8 hospitals)
            {
                "hospital_id": "HKB001",
                "name": "Basaveshwar Hospital",
                "location": "Kalaburagi",
                "district": "Kalaburagi",
                "contact_number": "08472-220555",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["Cardiology", "Neurology", "General Medicine"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HKB002",
                "name": "Kalaburagi Institute of Medical Sciences",
                "location": "Kalaburagi",
                "district": "Kalaburagi",
                "contact_number": "08472-220555",
                "total_beds": 500,
                "available_beds": 100,
                "icu_beds": 45,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HKB003",
                "name": "Sushruta Hospital",
                "location": "Kalaburagi",
                "district": "Kalaburagi",
                "contact_number": "08472-220555",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HKB004",
                "name": "Karnataka Hospital",
                "location": "Kalaburagi",
                "district": "Kalaburagi",
                "contact_number": "08472-220555",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HKB005",
                "name": "Sangameshwar Hospital",
                "location": "Kalaburagi",
                "district": "Kalaburagi",
                "contact_number": "08472-220555",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HKB006",
                "name": "Karnataka Institute of Medical Sciences",
                "location": "Kalaburagi",
                "district": "Kalaburagi",
                "contact_number": "08472-220555",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HKB007",
                "name": "Sushruta Hospital",
                "location": "Kalaburagi",
                "district": "Kalaburagi",
                "contact_number": "08472-220555",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HKB008",
                "name": "Karnataka Institute of Medical Sciences",
                "location": "Kalaburagi",
                "district": "Kalaburagi",
                "contact_number": "08472-220555",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            # Shivamogga (8 hospitals)
            {
                "hospital_id": "HSM001",
                "name": "McGann Hospital",
                "location": "Shivamogga",
                "district": "Shivamogga",
                "contact_number": "08182-225555",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["Cardiology", "Neurology", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HSM002",
                "name": "Shivamogga Institute of Medical Sciences",
                "location": "Shivamogga",
                "district": "Shivamogga",
                "contact_number": "08182-225555",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HSM003",
                "name": "Sushruta Hospital",
                "location": "Shivamogga",
                "district": "Shivamogga",
                "contact_number": "08182-225555",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HSM004",
                "name": "Karnataka Hospital",
                "location": "Shivamogga",
                "district": "Shivamogga",
                "contact_number": "08182-225555",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HSM005",
                "name": "Sangameshwar Hospital",
                "location": "Shivamogga",
                "district": "Shivamogga",
                "contact_number": "08182-225555",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HSM006",
                "name": "Karnataka Institute of Medical Sciences",
                "location": "Shivamogga",
                "district": "Shivamogga",
                "contact_number": "08182-225555",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HSM007",
                "name": "Sushruta Hospital",
                "location": "Shivamogga",
                "district": "Shivamogga",
                "contact_number": "08182-225555",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HSM008",
                "name": "Karnataka Hospital",
                "location": "Shivamogga",
                "district": "Shivamogga",
                "contact_number": "08182-225555",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            # Tumakuru (8 hospitals)
            {
                "hospital_id": "HTM001",
                "name": "Siddaganga Hospital",
                "location": "Tumakuru",
                "district": "Tumakuru",
                "contact_number": "0816-2277777",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["Cardiology", "Neurology", "General Medicine"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HTM002",
                "name": "Tumakuru Institute of Medical Sciences",
                "location": "Tumakuru",
                "district": "Tumakuru",
                "contact_number": "0816-2277777",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HTM003",
                "name": "Sushruta Hospital",
                "location": "Tumakuru",
                "district": "Tumakuru",
                "contact_number": "0816-2277777",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HTM004",
                "name": "Karnataka Hospital",
                "location": "Tumakuru",
                "district": "Tumakuru",
                "contact_number": "0816-2277777",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HTM005",
                "name": "Sangameshwar Hospital",
                "location": "Tumakuru",
                "district": "Tumakuru",
                "contact_number": "0816-2277777",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HTM006",
                "name": "Karnataka Institute of Medical Sciences",
                "location": "Tumakuru",
                "district": "Tumakuru",
                "contact_number": "0816-2277777",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HTM007",
                "name": "Sushruta Hospital",
                "location": "Tumakuru",
                "district": "Tumakuru",
                "contact_number": "0816-2277777",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HTM008",
                "name": "Karnataka Hospital",
                "location": "Tumakuru",
                "district": "Tumakuru",
                "contact_number": "0816-2277777",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            
            # Vijayapura (8 hospitals)
            {
                "hospital_id": "HVJ001",
                "name": "Al-Ameen Medical College Hospital",
                "location": "Bijapur, Vijayapura",
                "district": "Vijayapura",
                "contact_number": "08352-255555",
                "total_beds": 500,
                "available_beds": 100,
                "icu_beds": 40,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics", "Cardiology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HVJ002",
                "name": "BLDEA's Shri B M Patil Medical College Hospital",
                "location": "Bijapur, Vijayapura",
                "district": "Vijayapura",
                "contact_number": "08352-262770",
                "total_beds": 600,
                "available_beds": 120,
                "icu_beds": 50,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics", "Cardiology", "Neurology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HVJ003",
                "name": "District Hospital Vijayapura",
                "location": "Bijapur, Vijayapura",
                "district": "Vijayapura",
                "contact_number": "08352-250200",
                "total_beds": 400,
                "available_beds": 80,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HVJ004",
                "name": "Sangolli Rayanna Hospital",
                "location": "Bijapur, Vijayapura",
                "district": "Vijayapura",
                "contact_number": "08352-255555",
                "total_beds": 300,
                "available_beds": 60,
                "icu_beds": 25,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HVJ005",
                "name": "KLE's Dr. Prabhakar Kore Hospital",
                "location": "Bijapur, Vijayapura",
                "district": "Vijayapura",
                "contact_number": "08352-262770",
                "total_beds": 450,
                "available_beds": 90,
                "icu_beds": 35,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics", "Cardiology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HVJ006",
                "name": "Siddharth Hospital",
                "location": "Bijapur, Vijayapura",
                "district": "Vijayapura",
                "contact_number": "08352-255555",
                "total_beds": 250,
                "available_beds": 50,
                "icu_beds": 20,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HVJ007",
                "name": "Basaveshwar Teaching and General Hospital",
                "location": "Bijapur, Vijayapura",
                "district": "Vijayapura",
                "contact_number": "08352-255555",
                "total_beds": 350,
                "available_beds": 70,
                "icu_beds": 30,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics", "Cardiology"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            },
            {
                "hospital_id": "HVJ008",
                "name": "Sushruta Hospital",
                "location": "Bijapur, Vijayapura",
                "district": "Vijayapura",
                "contact_number": "08352-255555",
                "total_beds": 200,
                "available_beds": 40,
                "icu_beds": 15,
                "specialties": ["General Medicine", "Pediatrics", "Orthopedics"],
                "ambulance_services": True,
                "mental_health_support": True,
                "financial_assistance": True
            }
        ]
        
        # Insert hospitals into MongoDB
        for hospital in hospitals:
            # Check if hospital already exists
            existing_hospital = hospitals_collection.find_one({"hospital_id": hospital["hospital_id"]})
            if not existing_hospital:
                hospitals_collection.insert_one(hospital)
                logger.info(f"Added hospital: {hospital['name']} in {hospital['district']}")
        
        logger.info("Successfully added hospitals across all Karnataka districts")
        return True
    except Exception as e:
        logger.error(f"Error adding Karnataka hospitals: {str(e)}")
        return False

# Call the function when the app starts
add_karnataka_hospitals()

@app.route('/api/hospitals/<district>')
@login_required
def get_hospitals_by_district(district):
    """Get hospitals for a specific district"""
    try:
        hospitals_collection = get_hospitals_collection()
        hospitals = list(hospitals_collection.find({"district": district}))
        
        # Convert ObjectId to string for JSON serialization
        for hospital in hospitals:
            hospital['_id'] = str(hospital['_id'])
        
        logger.info(f"API: Loaded {len(hospitals)} hospitals for district: {district}")
        return jsonify(hospitals)
        
    except Exception as e:
        logger.error(f"API: Error loading hospitals for district {district}: {str(e)}")
        return jsonify({"error": "Failed to load hospitals"}), 500

def init_db():
    """Initialize the MongoDB database with required collections and indexes"""
    try:
        # Ensure MongoDB connection is established
        if mongo_client is None:
            logger.error("MongoDB connection not established")
            return False

        # Initialize collections if they don't exist
        collections = ['patients', 'ambulance_requests', 'pros', 'users']
        for collection in collections:
            if collection not in db.list_collection_names():
                db.create_collection(collection)
                logger.info(f"Created collection: {collection}")

        # Create indexes
        db.patients.create_index([("patient_id", 1)], unique=True)
        db.patients.create_index([("nursing_home_id", 1)])
        db.ambulance_requests.create_index([("request_id", 1)], unique=True)
        db.ambulance_requests.create_index([("patient_id", 1)])
        db.pros.create_index([("pro_id", 1)], unique=True)
        db.users.create_index([("username", 1)], unique=True)
        db.users.create_index([("email", 1)], unique=True)

        logger.info("Database initialization completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return False

def init_session_data():
    """Initialize session data for the logged-in user"""
    try:
        # Get the nursing home's ID from session
        nursing_home_id = session.get('entity_id')
        if not nursing_home_id:
            raise Exception("No entity_id found in session")
        
        # Get nursing home details
        nursing_home = db.users.find_one(
            {'entity_id': nursing_home_id},
            {'_id': 0, 'password': 0}  # Exclude sensitive fields
        )
        
        if not nursing_home:
            raise Exception("Nursing home not found in database")
        
        # Get all patients for this nursing home
        patients = list(db.patients.find(
            {'admitted_by': nursing_home_id},
            {'_id': 0}  # Exclude MongoDB _id field
        ))
        
        # Get all hospitals
        hospitals = list(db.multispeciality_hospitals.find(
            {},
            {'_id': 0}  # Exclude MongoDB _id field
        ))
        
        # Update session with the data
        session['nursing_home'] = nursing_home
        session['patients'] = patients
        session['hospitals'] = hospitals
        session.modified = True
        
        logger.info(f"Successfully initialized session data for nursing home: {nursing_home_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error initializing session data: {str(e)}")
        raise

def cleanup_collections():
    """Remove unwanted collections from the database"""
    try:
        # List of collections we want to keep
        required_collections = ['users', 'patients', 'multispeciality_hospitals']
        
        # Get all collections
        collections = db.list_collection_names()
        logger.info(f"Current collections: {collections}")
        
        # Remove unwanted collections
        for collection in collections:
            if collection not in required_collections:
                logger.info(f"Dropping collection: {collection}")
                db[collection].drop()
        
        logger.info("Database cleanup completed")
        return True
    except Exception as e:
        logger.error(f"Error cleaning up collections: {str(e)}")
        return False

# Add this to the init_db function
def init_db():
    """Initialize the database with required data"""
    try:
        # Initialize MongoDB connection
        if not init_mongodb():
            raise Exception("Failed to initialize MongoDB connection")
        
        # Clean up unwanted collections
        cleanup_collections()
        
        # Add hospitals if collection is empty
        hospitals_count = db.multispeciality_hospitals.count_documents({})
        if hospitals_count == 0:
            add_karnataka_hospitals()
            logger.info("Added Karnataka hospitals to database")
        
        logger.info("Database initialization completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return False

# Initialize the database when the application starts
if __name__ == '__main__':
    if init_db():
        app.run(debug=True)
    else:
        logger.error("Failed to initialize database. Application cannot start.")