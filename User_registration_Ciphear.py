import json
import boto3
import hashlib
import random
import uuid
import os
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
cognito = boto3.client('cognito-idp')
sns = boto3.client('sns')

def lambda_handler(event, context):
    print(f"Registration event: {json.dumps(event)}")
    
    try:
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
        
        email = body.get('email', '').strip().lower()
        password = body.get('password', '')
        user_type = body.get('userType', 'customer').lower()
        security_question = body.get('securityQuestion', '').strip()
        security_answer = body.get('securityAnswer', '').strip()
        
        if not all([email, password, security_question, security_answer]):
            return response_with_cors(400, {'error': 'Missing required fields: email, password, securityQuestion, securityAnswer'})
        
        if user_type not in ['customer', 'franchise']:
            return response_with_cors(400, {'error': 'userType must be either "customer" or "franchise"'})
        
        if len(password) < 8:
            return response_with_cors(400, {'error': 'Password must be at least 8 characters long'})
        
        users_table = dynamodb.Table(os.environ['USERS_TABLE'])
        existing_user = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        
        if existing_user['Items']:
            return response_with_cors(400, {'error': 'User with this email already exists'})
        
        user_id = str(uuid.uuid4())
        
        try:
            cognito_response = cognito.sign_up(
                ClientId=os.environ['COGNITO_CLIENT_ID'],
                Username=email,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'custom:user_type', 'Value': user_type}
                ]
            )
            
            print(f"Cognito user created: {email}")
            
        except cognito.exceptions.UsernameExistsException:
            return response_with_cors(400, {'error': 'User already exists in the system'})
        except Exception as e:
            print(f"Cognito error: {str(e)}")
            return response_with_cors(400, {'error': f'User creation failed: {str(e)}'})
        
        users_table.put_item(
            Item={
                'userId': user_id,
                'email': email,
                'userType': user_type,
                'registrationDate': datetime.now().isoformat(),
                'isActive': True,
                'verificationStatus': 'pending',
                'cognitoUsername': email
            }
        )
        
        security_table = dynamodb.Table(os.environ['SECURITY_QUESTIONS_TABLE'])
        caesar_challenge = generate_caesar_challenge()
        
        security_table.put_item(
            Item={
                'userId': user_id,
                'securityQuestion': security_question,
                'securityAnswer': hashlib.sha256(security_answer.lower().strip().encode()).hexdigest(),
                'caesarChallenge': caesar_challenge,
                'createdAt': datetime.now().isoformat()
            }
        )
        
        send_registration_notification(email, user_id, user_type)
        
        print(f"User registered successfully: {user_id}")
        
        return response_with_cors(200, {
            'message': 'User registered successfully! Please check your email for verification code.',
            'userId': user_id,
            'email': email,
            'userType': user_type,
            'verificationRequired': True,
            'nextStep': 'Please verify your email address using the code sent to your email.'
        })
        
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return response_with_cors(500, {'error': 'Internal server error'})

def send_registration_notification(email, user_id, user_type):
    try:
        topic_arn = os.environ.get('REGISTRATION_TOPIC_ARN', '')
        if not topic_arn:
            print("No registration topic ARN configured, skipping notification")
            return
        
        message = {
            'email': email,
            'userId': user_id,
            'userType': user_type,
            'timestamp': datetime.now().isoformat(),
            'event': 'user_registered'
        }
        
        sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message),
            Subject=f'DALScooter Registration - {email}'
        )
        
        print(f"Registration notification sent for user: {user_id}")
        
    except Exception as e:
        print(f"Error sending registration notification: {str(e)}")

def generate_caesar_challenge():
    words = ['CLOUD', 'SERVERLESS', 'LAMBDA', 'DYNAMO', 'COGNITO', 'GATEWAY', 'SECURE', 'CRYPTO']
    word = random.choice(words)
    shift = random.randint(1, 25)
    
    encoded = ""
    for char in word:
        if char.isalpha():
            encoded += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            encoded += char
    
    return {
        'originalWord': word,
        'encodedWord': encoded,
        'shift': shift,
        'hint': f"Decode this word using Caesar cipher (shift by {shift}): {encoded}",
        'instructions': f"Each letter is shifted {shift} positions forward in the alphabet"
    }

def response_with_cors(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'POST,OPTIONS',
            'Content-Type': 'application/json'
        },
        'body': json.dumps(body)
    }