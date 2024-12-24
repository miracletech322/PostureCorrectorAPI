from flask import Flask, render_template, url_for, request, session, redirect,jsonify
from flask_pymongo import PyMongo
import json
import bcrypt
from bson import json_util, ObjectId
from datetime import datetime,timedelta
import uuid

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json_util.default(o)

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'electronapp'
app.config['MONGO_URI'] = 'mongodb+srv://djangoprodev:IU7le4GHEIwhaBQC@cluster0.r1cun.mongodb.net/electronapp'

mongo = PyMongo(app)

@app.route('/')
def index():
    if 'username' in session:
        return 'You are logged in as ' + session['username']

    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    login_user = users.find_one({'name' : request.form['username']})

    if login_user:
        if bcrypt.hashpw(request.form['pass'].encode('utf-8'), login_user['password'].encode('utf-8')) == login_user['password'].encode('utf-8'):
            session['username'] = request.form['username']
            return redirect(url_for('index'))

    return 'Invalid username/password combination'

@app.route('/api/register', methods=['POST'])
def api_register():
    if request.is_json:
        users = mongo.db.users
        existing_email = users.find_one({'email': request.json['email']})

        if existing_email is None:
            # Generate a unique account_id
            account_id = str(uuid.uuid4())

            hashpass = bcrypt.hashpw(request.json['password'].encode('utf-8'), bcrypt.gensalt())
            paid_account = request.json.get('paid_account', False)
            account_type = request.json.get('account_type', '').lower()  # Make the account_type lowercase
            employees_number = request.json.get('employees_number', 0) if account_type == 'corporal' else 0

            # Debugging statements
            print(f"Account Type: {account_type}")
            print(f"Employees Number: {employees_number}")
            print(f"Account Type Check: {'Corporal' if account_type == 'corporal' else 'Not Corporal'}")

            users.insert_one({
                'account_id': account_id,
                'first_name': request.json['first_name'],
                'last_name': request.json['last_name'],
                'gender': request.json['gender'],
                'email': request.json['email'],
                'password': hashpass,
                'account_type': account_type,
                'paid_account': paid_account,
                'employees_number': employees_number if account_type == 'corporal' else 0,
                'active': 0 if account_type == 'corporal' else None,
                'available': employees_number if account_type == 'corporal' else 0,
                'streak': 1  # Initialize streak to 1
            })
            return jsonify({'message': 'User created successfully', 'account_id': account_id}), 201

        return jsonify({'error': 'That email already exists!'}), 409

    return jsonify({'error': 'Invalid request'}), 400

@app.route('/api/change_password', methods=['PUT'])
def api_change_password():
    if request.is_json:
        users = mongo.db.users
        existing_user = users.find_one({'email': request.json['email']})

        if existing_user and bcrypt.checkpw(request.json['current_password'].encode('utf-8'), existing_user['password']):
            new_password_hash = bcrypt.hashpw(request.json['new_password'].encode('utf-8'), bcrypt.gensalt())
            users.update_one(
                {'email': request.json['email']},
                {'$set': {'password': new_password_hash}}
            )
            return jsonify({'message': 'Password changed successfully'}), 200

        return jsonify({'error': 'Invalid current password'}), 401

    return jsonify({'error': 'Invalid request'}), 400

@app.route('/api/delete_employees', methods=['POST'])
def api_delete_employees():
    if request.is_json:
        users = mongo.db.users
        corporate_email = request.json.get('corporate_email')

        if corporate_email:
            result = users.delete_many({'corporate_email': corporate_email, 'account_type': 'employee'})
            if result.deleted_count > 0:
                # Update the corporate account's available field
                users.update_one(
                    {'email': corporate_email},
                    {'$inc': {'available': result.deleted_count}}
                )
                return jsonify({'message': f'{result.deleted_count} employee accounts deleted successfully'}), 200
            else:
                return jsonify({'message': 'No employee accounts found to delete'}), 200

        return jsonify({'error': 'Corporate email not provided'}), 400

    return jsonify({'error': 'Invalid request'}), 400

@app.route('/api/login', methods=['POST'])
def api_login():
    if request.is_json:
        users = mongo.db.users
        existing_user = users.find_one({'email': request.json['email']})

        if existing_user and bcrypt.checkpw(request.json['password'].encode('utf-8'), existing_user['password']):
            # Update the last_signed_in field
            users.update_one(
                {'email': request.json['email']},
                {'$set': {'last_signed_in': datetime.utcnow()}}
            )

            # Update the streak field
            last_signed_in = existing_user.get('last_signed_in', None)
            if last_signed_in:
                if (datetime.utcnow() - last_signed_in) <= timedelta(days=1):
                    streak = existing_user.get('streak', 1)
                else:
                    streak = existing_user.get('streak', 1) + 1
            else:
                streak = 1

            users.update_one(
                {'email': request.json['email']},
                {'$set': {'streak': max(streak, 1)}}
            )

            user_data = {
                'account_id': existing_user['account_id'],
                'first_name': existing_user['first_name'],
                'last_name': existing_user['last_name'],
                'gender': existing_user['gender'],
                'email': existing_user['email'],
                'account_type': existing_user['account_type'],
                'paid_account': existing_user.get('paid_account', False),
                'last_signed_in': existing_user.get('last_signed_in', None),
                'elapsed_time': existing_user.get('elapsed_time', None),
                'employees_number': existing_user['employees_number'],
                'streak': streak  # Include streak in user data
            }
            return jsonify(user_data), 200

        return jsonify({'error': 'Invalid email or password'}), 401

    return jsonify({'error': 'Invalid request'}), 400


@app.route('/api/create_employee', methods=['POST'])
def api_create_employee():
    if request.is_json:
        users = mongo.db.users
        corporate_email = request.json['corporate_email']

        corporate_account = users.find_one({'email': corporate_email})

        

        if corporate_account and corporate_account['account_type'].lower() == 'corporal':
            employees_number = corporate_account.get('employees_number', 0)
            available = corporate_account.get('available', 0)
            existing_employees = users.count_documents({'corporate_email': corporate_email, 'account_type': 'employee'})

            

            if available == 0:
                return jsonify({'error': 'Account is fully seated. Upgrade for more seats.'}), 403

            if existing_employees < employees_number:
                hashpass = bcrypt.hashpw(request.json['password'].encode('utf-8'), bcrypt.gensalt())
                account_id = str(uuid.uuid4())

                users.insert_one({
                    'account_id': account_id,
                    'first_name': 'Employee',
                    'last_name': None,
                    'gender': None,
                    'email': request.json['email'],
                    'password': hashpass,
                    'account_type': 'employee',
                    'corporate_email': corporate_email,
                    'paid_account': True,
                    'employees_number': 0
                })

                # Update the corporate account's available and active fields
                users.update_one(
                    {'email': corporate_email},
                    {'$inc': {'available': -1}, '$set': {'active': existing_employees + 1}}
                )

                user_data = {
                    'account_id': account_id,
                    'first_name': 'Employee',
                    'last_name': None,
                    'gender': None,
                    'email': request.json['email'],
                    'account_type': 'employee',
                    'paid_account': False,
                    'last_signed_in': None,
                    'elapsed_time': None
                }

                return jsonify(user_data), 201

            return jsonify({'error': 'Maximum number of employees reached'}), 403

        return jsonify({'error': 'Corporate account not found or not authorized'}), 404

    return jsonify({'error': 'Invalid request'}), 400


@app.route('/api/get_employee_data', methods=['POST'])
def get_employee_data():
    if request.is_json:
        corporate_email = request.json.get('corporate_email')
        print(corporate_email)
        if not corporate_email:
            return jsonify({'error': 'Corporate email is required'}), 400

        users = mongo.db.users
        related_accounts = users.find({'corporate_email': corporate_email})

        # Debugging statement to check the number of documents found
        count = users.count_documents({'corporate_email': corporate_email})
        print(f"Number of related accounts found: {count}")

        result = []
        for account in related_accounts:
            # Debugging statement to print each account found
            print(f"Account found: {account}")
            result.append({
                "email": account["email"],
                "corporate_email": account["corporate_email"],
                "active": "Active" if account.get("status", False) else "Inactive"
            })

        return jsonify(result), 200

    return jsonify({'error': 'Invalid request'}), 400


@app.route('/api/delete_employee', methods=['POST'])
def delete_employee():
    data = request.get_json()
    email = data.get('email')
    corporate_email = data.get('corporate_email')
    print(email)
    print(corporate_email)
    if not email or not corporate_email:
        return jsonify({'error': 'Email and corporate email are required'}), 400

    # Find the account with the specified email, account_type, and corporate_email
    account = mongo.db.users.find_one({
        'email': email,
        'account_type': 'employee',
        'corporate_email': corporate_email
    })

    if not account:
        return jsonify({'error': 'Account not found'}), 404

    # Delete the account
    result = mongo.db.users.delete_one({'_id': account['_id']})

    if result.deleted_count == 1:
        return jsonify({'message': 'Account deleted successfully'}), 200
    else:
        return jsonify({'error': 'Failed to delete account'}), 500

@app.route('/api/user_data/<email>', methods=['GET'])
def api_user_data(email):
    users = mongo.db.users
    corporate_account = users.find_one({'email': email})

    if corporate_account:
        existing_employees = users.count_documents({'corporate_email': email, 'account_type': 'employee'})
        user_data = {
            'employees_number': corporate_account.get('employees_number', 0),
            'existing_employees': existing_employees
        }
        return jsonify(user_data), 200

    return jsonify({'error': 'Corporate account not found'}), 404



@app.route('/api/paid_account/<email>', methods=['PUT'])
def api_paid_account(email):
    if request.is_json:
        users = mongo.db.users
        existing_user = users.find_one({'email' : email})

        if existing_user:
            users.update_one({'email': email}, {'$set': {'paid_account': True}})
            return jsonify({'message': 'Account updated successfully'}), 200

        return jsonify({'error': 'User not found'}), 404

    return jsonify({'error': 'Invalid request'}), 400

def print_db_contents():
    users = mongo.db.users
    cursor = users.find()
    for document in cursor:
        print(document)

@app.route('/api/db')
def api_db():
    print_db_contents()
    return 'Database contents printed to terminal'

@app.route('/api/update_profile', methods=['PUT'])
def api_update_profile():
    if request.is_json:
        users = mongo.db.users
        existing_user = users.find_one({'email': request.json['email']})

        if existing_user:
            users.update_one(
                {'email': request.json['email']},
                {'$set': {
                    'first_name': request.json['first_name'],
                    'email': request.json['email'],
                    'account_id': request.json['account_id']
                }}
            )
            return jsonify({'message': 'Profile updated successfully'}), 200

        return jsonify({'error': 'Email cannot be changed'}), 404

    return jsonify({'error': 'Invalid request'}), 400


@app.route('/api/upload_image', methods=['POST'])
def api_upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        # Save the file to a directory (e.g., 'uploads/')
        file.save(f'uploads/{file.filename}')
        return jsonify({'message': 'File uploaded successfully'}), 200

    return jsonify({'error': 'File upload failed'}), 500

@app.route('/api/check-email', methods=['POST'])
def api_check_email():
    if request.is_json:
        users = mongo.db.users
        email = request.json.get('email')

        if email:
            existing_user = users.find_one({'email': email})
            if existing_user:
                return jsonify({'exists': True}), 200
            else:
                return jsonify({'exists': False}), 200

        return jsonify({'error': 'Email not provided'}), 400

    return jsonify({'error': 'Invalid request'}), 400

@app.route('/api/change_password_by_email', methods=['POST'])
def api_change_password_by_email():
    if request.is_json:
        users = mongo.db.users
        email = request.json.get('email')
        new_password = request.json.get('new_password')

        print(f"Received request with email: {email} and new_password: {new_password}")

        if email and new_password:
            existing_user = users.find_one({'email': email})

            if existing_user:
                new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                users.update_one(
                    {'email': email},
                    {'$set': {'password': new_password_hash}}
                )
                print("Password updated successfully")
                return jsonify({'message': 'Password changed successfully'}), 200

            print("Email not found")
            return jsonify({'error': 'Email not found'}), 404

        print("Email and new password are required")
        return jsonify({'error': 'Email and new password are required'}), 400

    print("Invalid request")
    return jsonify({'error': 'Invalid request'}), 400

if __name__ == '__main__':
    app.secret_key = 'mysecret'
    app.run(host='0.0.0.0', port=5000)
