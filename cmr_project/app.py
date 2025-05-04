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
        
        # Create nursing_homes collection if it doesn't exist
        if 'nursing_homes' not in collections:
            db.create_collection('nursing_homes')
            db['nursing_homes'].create_index([("email", 1)], unique=True)
            db['nursing_homes'].create_index([("nursing_home_details.phone", 1)], unique=True)
            logger.info("Created nursing_homes collection with indexes")
        
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

# Function to initialize nursing home credentials
def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def init_nursing_home_credentials():
    """Initialize nursing home credentials in MongoDB"""
    try:
        for home in healthcare_data['nursing_homes']:
            # Check if nursing home exists in MongoDB
            existing_home = db.nursing_homes.find_one({'entity_id': home['clinic_id']})
            if not existing_home:
                # Create default username and password
                username = f"clinic_{home['clinic_id'].lower()}"
                password = f"{home['clinic_id']}123"
                
                # Create a single document with both user and nursing home details
                nursing_home_doc = {
                    'username': username,
                    'password': hash_password(password),
                    'role': 'nursing_home',
                    'entity_id': home['clinic_id'],
                    'nursing_home_details': {
                        'name': home['name'],
                        'location': home['location'],
                        'contact_person': home['contact_person'],
                        'phone': home['phone'],
                        'email': home['email']
                    },
                    'created_at': datetime.utcnow()
                }
                
                # Insert into MongoDB nursing_homes collection
                db.nursing_homes.insert_one(nursing_home_doc)
                logger.info(f"Created credentials for nursing home: {home['name']}")
        
        logger.info("Nursing home credentials initialized successfully in MongoDB")
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
            # Try to find nursing home by email or phone
            nursing_home = db.nursing_homes.find_one({
                '$or': [
                    {'email': login_id},
                    {'nursing_home_details.phone': login_id}
                ]
            })
            
            if not nursing_home:
                flash('No account found with this email or phone number', 'error')
                return render_template('nursing_home_login.html')
            
            if nursing_home['password'] != hash_password(password):
                flash('Invalid password', 'error')
                return render_template('nursing_home_login.html')
            
            # Set session data
            session['user_id'] = str(nursing_home['_id'])
            session['username'] = nursing_home['username']
            session['role'] = nursing_home['role']
            session['entity_id'] = nursing_home['entity_id']
            
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
            
            # Debug logging
            logger.info(f"Attempting to register nursing home with email: {email}")
            
            # Validate required fields
            if not all([name, location, contact_person, phone, email, password, confirm_password]):
                flash('Please fill in all fields', 'error')
                return render_template('signup.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('signup.html')
            
            # Check if email already exists - using the correct field path
            existing_nursing_home = db.nursing_homes.find_one({'nursing_home_details.email': email})
            logger.info(f"Existing nursing home check result: {existing_nursing_home}")
            
            if existing_nursing_home:
                flash('Email already exists', 'error')
                return render_template('signup.html')
            
            # Check if phone number already exists
            existing_phone = db.nursing_homes.find_one({'nursing_home_details.phone': phone})
            logger.info(f"Existing phone check result: {existing_phone}")
            
            if existing_phone:
                flash('Phone number already registered', 'error')
                return render_template('signup.html')
            
            # Generate nursing home ID
            nursing_home_id = f"NH{str(uuid.uuid4())[:8]}"
            
            # Create nursing home document
            nursing_home_doc = {
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
                    'phone': phone,
                    'email': email  # Also store email in nursing_home_details
                }
            }
            
            # Debug logging before insert
            logger.info(f"Attempting to insert nursing home document: {nursing_home_doc}")
            
            # Insert nursing home into MongoDB
            result = db.nursing_homes.insert_one(nursing_home_doc)
            
            if result.inserted_id:
                logger.info(f"Successfully inserted nursing home with ID: {result.inserted_id}")
                # Initialize nursing home collection
                init_nursing_home_collection(nursing_home_id)
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('nursing_home_login'))
            else:
                logger.error("Failed to insert nursing home document")
                flash('Registration failed. Please try again.', 'error')
                
        except Exception as e:
            logger.error(f"Signup error: {str(e)}", exc_info=True)
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('signup.html')

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

def init_session_data():
    """Initialize session data for the logged-in nursing home"""
    try:
        # Get the nursing home's ID from session
        nursing_home_id = session.get('entity_id')
        if not nursing_home_id:
            raise Exception("No entity_id found in session")
        
        # Get nursing home details
        nursing_home = db.nursing_homes.find_one(
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
        required_collections = ['nursing_homes', 'patients', 'multispeciality_hospitals']
        
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

# Initialize the database when the application starts
if __name__ == '__main__':
    if init_db():
        app.run(debug=True)
    else:
        logger.error("Failed to initialize database. Application cannot start.")