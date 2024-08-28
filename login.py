from flask import (Flask,jsonify,request)
from flask_restful import Api
import pymongo, re,jwt
from werkzeug.security import generate_password_hash, check_password_hash   # generate password hash 
import uuid as uuid 
from datetime import datetime, timedelta, timezone
# for timezone()
import pytz

app = Flask(__name__)  
api = Api(app)

#-connect mongodb
mongo = pymongo.MongoClient("mongodb://localhost:27017/")
db = mongo["user_details"]

app.config['SECRET_KEY'] = 'secretkey'
# Define a secret key for JWT
JWT_SECRET_KEY = 'jwt_secret_key'

#---email and username validation
email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
username_regex = re.compile(r"^[a-zA-Z0-9_]{3,10}$")

#----------------------password validation--------------------------
def validate_password(password):
    pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,16}$'
    match = re.search(pattern, password)
    return match is not None

#---------------generate access token------------------------
def generate_access_token(email):
    access_token_expire = datetime.utcnow() + timedelta(minutes=3)  # Short-lived token
    access_payload = {
        'email': email,
        'exp': access_token_expire
    }
    access_token = jwt.encode(access_payload, JWT_SECRET_KEY, algorithm="HS256")
    return access_token

#---------------generate refresh token------------------------
def generate_refresh_token(email):
    refresh_token_expire = datetime.utcnow() + timedelta(days=7)  # Long-lived token
    refresh_payload = {
        'email': email,
        'exp': refresh_token_expire
    }
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET_KEY, algorithm="HS256")
    return refresh_token

#----------------------signup------------------------------
@app.route("/signup", methods=['POST'])
def signup():
    # required parameter
    required_params = ['email', 'password','username']
    data = request.form
    
    # Check if all required parameters are present
    missing_params = [param for param in required_params if param not in data]
    if missing_params:
        return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})  
    
    email = data["email"]
    password = data["password"]
    username = data["username"]

    # Validate password
    if not validate_password(password):
        return jsonify({"message":'Password must contain 8 to 16 characters,including at least alphanumeric,1 captial letter and special characters',"Success":False})    

    # Validate email
    elif not email_regex.match(email):
        return jsonify({"message": "Invalid email Format","Success":False})
    
    elif not username_regex.match(username):
        return jsonify({"message": "Username must contain minimum 3 to 10 characters","Success":False})

    elif db.user.find_one({"email": email}):
        return jsonify({"message": "Email already exists"}) 
    
    elif db.user.find_one({"username": username}):
        return jsonify({"message": "Username already exists"}) 
    
    # Hash the password
    hashed_password = generate_password_hash(password)
    
    db.user.insert_one({
        "email": email,
        "username": username,
        "password": hashed_password,
        "bank_balance": 0,
        "login_logout_history":[{
            "date": datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S'),
                    "action": "signup"
        }]
    })
    return jsonify({'message':'User registered successfully','success':True})

#-------------------------------login-----------------------------------------------------------------
@app.post("/login")
def login():
    required_params = ['email','password']
    data = request.form
    # Check if all required parameters are present
    missing_params = [param for param in required_params if param not in data]
    if missing_params:
        return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})
    email = data["email"]
    password = data["password"]
    user = db.user.find_one({"email": email})

    if not user:
        return jsonify({"message": "Sign up before login", "success": False})

    if user and check_password_hash(user['password'], password):
        # Generate access and refresh tokens
        access_token = generate_access_token(email)
        refresh_token = generate_refresh_token(email)
        db.user.update_one(
    {'email': email},
    {
        '$set': {
            'access_token': access_token,
            'refresh_token': refresh_token
        },
        '$push': {
            'login_logout_history': {
                'date': datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S'),
                'action': 'login'
                    }
                }
            }
        )

        return jsonify({'access_token':access_token, 'refresh_token':refresh_token ,
                        'message': 'Successful logged in', 'success': True,'token':"valid for 1 min"})
    else:
        return jsonify({"message": "Invalid email or password 1","success": "false"})
    
#-------------------user logout-----------------
@app.route('/logout', methods=['GET'])
def logout():
    jwtoken = request.headers.get('Authorization')
    if not jwtoken:
        return jsonify({'message': 'Missing authorization token', "success": False})

    try:
        # Split the Bearer token
        jwtoken = jwtoken.split(" ")[1]
        print(f"Token received: {jwtoken}")

        # Decode the JWT token
        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']
        print(f"Decoded token for email: {email}")

        # Find the user in the database
        admin = db.user.find_one({'email': email, 'access_token': jwtoken})
        if not admin:
            return jsonify({'message': 'Token is invalid', "success": False})

        # Update the user's token to invalidate it
        result = db.user.update_one({'email': email}, {"$set": {'access_token': None},
                            '$push': {
            'login_logout_history': {
                'date': datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S'),
                'action': 'logout'
                    }
                }   })
        if result.matched_count == 0:
            return jsonify({'message': 'Failed to log out', "success": False})
        return jsonify({'message': 'Logged out successfully', "success": True})

    except jwt.ExpiredSignatureError:
        admin = db.user.find_one({"access_token": jwtoken})
        if not admin:
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin.get('refresh_token')
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin['email'])
            
            # Update the new access token in MongoDB
            db.user.update_one({"email": admin['email']}, {"$set": {"access_token": new_access_token}})
            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        print("Invalid authorization token")
        return jsonify({'message': 'Invalid authorization token', 'success': False})

#------------add bank accounts----------------
@app.post('/add_bank_account')
def add_bank_account():
    jwtoken = request.headers.get('Authorization')
    if not jwtoken:
        return jsonify({'message': 'Missing authorization token', "success": False})

    try:
        # Split the Bearer token
        jwtoken = jwtoken.split(" ")[1]
        print(f"Token received: {jwtoken}")

        # Decode the JWT token
        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']
        print(f"Decoded token for email: {email}")

        # Find the user in the database
        admin = db.user.find_one({'email': email, 'access_token': jwtoken})
        if not admin:
            return jsonify({'message': 'Token is invalid', "success": False})
        
        required_params = ['bank_name','acc_no','ifsc']
        data = request.form
        # Check if all required parameters are present
        missing_params = [param for param in required_params if param not in data]
        if missing_params:
            return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})

        # Extract data from request
        data = request.form
        bank_name = data['bank_name']
        acc_no = data['acc_no']
        ifsc = data['ifsc']

        # Check if the bank account already exists
        existing_account = db.user.find_one({'email': email, 'bank_accounts.acc_no': acc_no})
        
        if existing_account:
            # Find the specific bank account entry
            account = next((acc for acc in existing_account['bank_accounts'] if acc['acc_no'] == acc_no), None)
            if account:
                if not account['active']:
                    # Reactivate the existing bank account
                    db.user.update_one(
                        {"email": email, "bank_accounts.acc_no": acc_no},
                        {"$set": {"bank_accounts.$.active": True}}
                    )

                    # Log the reactivation in the bank_accounts_history
                    db.user.update_one(
                        {"email": email},
                        {"$push": {"bank_accounts_history": {
                            "acc_no": acc_no,
                            "type": "reactivated",
                            "bank_name": account["bank_name"],
                            "balance": account.get("balance", 0),  # Assuming balance is stored, otherwise default to 0
                            "active": True,
                            "date_reactivated": datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S')
                        }}}
                    )
                    return jsonify({'message': 'Bank account reactivated successfully', "success": True})
                else:
                    return jsonify({'message': 'Bank account already exists and is active', "success": False})
        
        # Create a new bank account entry
        new_account = {
            'bank_name': bank_name,
            'acc_no': acc_no,
            'ifsc': ifsc,
            'active': True,
        }

        # Update the user's bank accounts array
        db.user.update_one(
            {"email": email},
            {"$push": {"bank_accounts": new_account}}
        )

        # Additionally, push the new account to the bank_accounts_history array
        db.user.update_one(
            {"email": email},
            {"$push": {"bank_accounts_history": {
                "acc_no": acc_no,
                "bank_name": bank_name,
                "balance": 0,  # New accounts start with a balance of 0
                "active": True,
                "date_added": datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S')
            }}}
        )

        return jsonify({"message": "Bank account added successfully", "success": True}), 200

    except jwt.ExpiredSignatureError:
        admin = db.user.find_one({"access_token": jwtoken})
        if not admin:
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin.get('refresh_token')
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin['email'])
            
            # Update the new access token in MongoDB
            db.user.update_one({"email": admin['email']}, {"$set": {"access_token": new_access_token}})
            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        print("Invalid authorization token")
        return jsonify({'message': 'Invalid authorization token', 'success': False}) 


#----------------------show bank balance---------------------
@app.get('/bank_balance')
def bank_balance():
    jwtoken = request.headers.get('Authorization')
    if not jwtoken:
        return jsonify({'message': 'Missing authorization token', "success": False})

    try:
        # Split the Bearer token
        jwtoken = jwtoken.split(" ")[1]
        print(f"Token received: {jwtoken}")

        # Decode the JWT token
        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']
        print(f"Decoded token for email: {email}")

        # Find the user in the database
        admin = db.user.find_one({'email': email, 'access_token': jwtoken})
        if not admin:
            return jsonify({'message': 'Token is invalid', "success": False})
        
        required_params = ['acc_no']
        data = request.form
        # Check if all required parameters are present
        missing_params = [param for param in required_params if param not in data]
        if missing_params:
            return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})

        data = request.form
        acc_no = data.get('acc_no')

        # Verify if the account number belongs to the user
        account = next((acc for acc in admin.get('bank_accounts', []) if acc['acc_no'] == acc_no), None)
        if not account:
            return jsonify({'message': 'Account number not found ', "success": False})
        
        if account['active'] == True:
            return jsonify({'message': 'Account balance', "Balance": account["balance"]})
        
        else:
            return jsonify({'message': 'Account Not found', "success":False})
        


    except jwt.ExpiredSignatureError:
        admin = db.user.find_one({"access_token": jwtoken})
        if not admin:
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin.get('refresh_token')
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin['email'])
            
            # Update the new access token in MongoDB
            db.user.update_one({"email": admin['email']}, {"$set": {"access_token": new_access_token}})
            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        print("Invalid authorization token")
        return jsonify({'message': 'Invalid authorization token', 'success': False})

#-----------deposit---------------
@app.route('/deposit', methods=['POST'])
def deposit():
    jwtoken = request.headers.get('Authorization')
    if not jwtoken:
        return jsonify({'message': 'Missing authorization token', "success": False})

    try:
        # Split the Bearer token
        jwtoken = jwtoken.split(" ")[1]
        print(f"Token received: {jwtoken}")

        # Decode the JWT token
        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']
        print(f"Decoded token for email: {email}")

        # Find the user in the database
        admin = db.user.find_one({'email': email, 'access_token': jwtoken})
        if not admin:
            return jsonify({'message': 'Token is invalid', "success": False})
        
        required_params = ['acc_no','amount']
        data = request.form
        # Check if all required parameters are present
        missing_params = [param for param in required_params if param not in data]
        if missing_params:
            return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})


        data = request.form
        acc_no = data.get('acc_no')
        amount = data.get('amount')
        try:
            amount = float(amount)
        except ValueError:
            return jsonify({'message': 'Invalid amount', "success": False}), 400

        if not acc_no or not amount:
            return jsonify({'message': 'Account number and amount are required', "success": False}), 400

        if amount <= 0:
            return jsonify({'message': 'Deposit amount must be greater than zero', "success": False}), 400

        # Verify if the account number belongs to the user
        account = next((acc for acc in admin.get('bank_accounts', []) if acc['acc_no'] == acc_no), None)
        if not account:
            return jsonify({'message': 'Account number not found ', "success": False}), 404
        
        if account['active'] == True:
            db.user.update_one(
                {"bank_accounts.acc_no": acc_no},
                {"$inc": {"bank_accounts.$.balance": amount},
                "$push": {"transactions": {
                    "acc_no": acc_no,
                    "type": "deposit",
                    "amount": amount,
                    "bank_name": account['bank_name'],
                    "date": datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S')
                }}}
            )

            return jsonify({"message": "Deposit successful", "success": True}), 200
        else: 
            return jsonify({"message": "account not found", "success": False}), 200

    except jwt.ExpiredSignatureError:
        admin = db.user.find_one({"access_token": jwtoken})
        if not admin:
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin.get('refresh_token')
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin['email'])
            
            # Update the new access token in MongoDB
            db.user.update_one({"email": admin['email']}, {"$set": {"access_token": new_access_token}})
            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        print("Invalid authorization token")
        return jsonify({'message': 'Invalid authorization token', 'success': False}) 
    
#-----------------------withdraw-------------
@app.route('/withdraw', methods=['POST'])
def withdraw():
    jwtoken = request.headers.get('Authorization')
    if not jwtoken:
        return jsonify({'message': 'Missing authorization token', "success": False})

    try:
        # Split the Bearer token
        jwtoken = jwtoken.split(" ")[1]
        print(f"Token received: {jwtoken}")

        # Decode the JWT token
        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']
        print(f"Decoded token for email: {email}")

        # Find the user in the database
        admin = db.user.find_one({'email': email, 'access_token': jwtoken})
        if not admin:
            return jsonify({'message': 'Token is invalid', "success": False})
        
        required_params = ['acc_no','amount']
        data = request.form
        # Check if all required parameters are present
        missing_params = [param for param in required_params if param not in data]
        if missing_params:
            return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})


        data = request.form
        acc_no = data.get('acc_no')
        amount = data.get('amount')

        if not acc_no or amount is None:
            return jsonify({'message': 'Account number and amount are required', "success": False}), 400

        try:
            amount = float(amount)
        except ValueError:
            return jsonify({'message': 'Invalid amount', "success": False}), 400

        if amount <= 0:
            return jsonify({'message': 'Withdrawal amount must be greater than zero', "success": False}), 400

        user = db.user.find_one({"bank_accounts.acc_no": acc_no})
        
        if not user:
            return jsonify({'message': 'Account number not found', "success": False}), 404

        # Verify if the account number belongs to the user
        account = next((acc for acc in admin.get('bank_accounts', []) if acc['acc_no'] == acc_no), None)
        if not account:
            return jsonify({'message': 'Account number not found ', "success": False})
        
        if account['active'] == True:
            if account['balance'] < amount:
                return jsonify({'message': 'Insufficient balance', "success": False})
            db.user.update_one(
                {"bank_accounts.acc_no": acc_no},
                {"$inc": {"bank_accounts.$.balance": -amount},
                "$push": {"transactions": {
                    "acc_no": acc_no,
                    "type": "withdraw",
                    "amount": amount,
                    "bank_name": account['bank_name'],
                    "date": datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S')
                }}}
            )
            return jsonify({"message": "Withdrawal successful", "success": True}), 200
        
        else:
            return jsonify({"message": "Account Not found", "success": False}), 200

    except jwt.ExpiredSignatureError:
        admin = db.user.find_one({"access_token": jwtoken})
        if not admin:
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin.get('refresh_token')
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin['email'])
            
            # Update the new access token in MongoDB
            db.user.update_one({"email": admin['email']}, {"$set": {"access_token": new_access_token}})
            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        print("Invalid authorization token")
        return jsonify({'message': 'Invalid authorization token', 'success': False}) 
    
#-----------delete bank accounts---------------
@app.route('/delete_bank_account', methods=['POST'])
def delete_bank_account():
    jwtoken = request.headers.get('Authorization')
    if not jwtoken:
        return jsonify({'message': 'Missing authorization token', "success": False})

    try:
        # Split the Bearer token
        jwtoken = jwtoken.split(" ")[1]
        print(f"Token received: {jwtoken}")

        # Decode the JWT token
        decoded_token = jwt.decode(jwtoken, JWT_SECRET_KEY, algorithms=["HS256"])
        email = decoded_token['email']
        print(f"Decoded token for email: {email}")

        # Find the user in the database
        admin = db.user.find_one({'email': email, 'access_token': jwtoken})
        if not admin:
            return jsonify({'message': 'Token is invalid', "success": False})
        
        required_params = ['acc_no']
        data = request.form
        # Check if all required parameters are present
        missing_params = [param for param in required_params if param not in data]
        if missing_params:
            return jsonify({'message': f'Missing parameters: {", ".join(missing_params)}', 'success': False})


        data = request.form
        acc_no = data.get('acc_no')

        if not acc_no:
            return jsonify({'message': 'Account number is required', "success": False}), 400

        account = db.user.find_one(
            {"email": email, "bank_accounts.acc_no": acc_no},
            {"bank_accounts.$": 1}
        )

        if not account:
            return jsonify({'message': 'Bank account not found', "success": False}), 404
        
        # Verify if the account number belongs to the user
        account = next((acc for acc in admin.get('bank_accounts', []) if acc['acc_no'] == acc_no), None)
        if not account:
            return jsonify({'message': 'Account number not found ', "success": False}), 404

        # Mark the account as inactive
        db.user.update_one(
            {"email": email, "bank_accounts.acc_no": acc_no},
            {"$set": {"bank_accounts.$.active": False},
             "$push": {"bank_accounts_history": {
                "acc_no": acc_no,
                "type":"inactive",
                # "bank_name": account["bank_accounts"][0].get("bank_name"),
                # "balance": account["bank_accounts"][0].get("balance"),
                "bank_name": account["bank_name"],
                "balance": account["balance"],
                "active": False,
                "date_deleted": datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S')
             }}}
        )

        return jsonify({"message": "Bank account marked as deleted successfully", "success": True}), 200


    except jwt.ExpiredSignatureError:
        admin = db.user.find_one({"access_token": jwtoken})
        if not admin:
            return jsonify({'message': 'Access token is invalid or expired', 'success': False})

        refresh_token = admin.get('refresh_token')
        try:
            jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            new_access_token = generate_access_token(admin['email'])
            
            # Update the new access token in MongoDB
            db.user.update_one({"email": admin['email']}, {"$set": {"access_token": new_access_token}})
            return jsonify({'message': 'Token refreshed', 'new_access_token': new_access_token, 'success': True})

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Refresh token has expired, please log in again', 'success': False})
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid refresh token', 'success': False})

    except jwt.InvalidTokenError:
        print("Invalid authorization token")
        return jsonify({'message': 'Invalid authorization token', 'success': False}) 
    
#-----------------port-------------------
if __name__ == '__main__':
    app.run(port=3000,host='0.0.0.0',debug=True)

