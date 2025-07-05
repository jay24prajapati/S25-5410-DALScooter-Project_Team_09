import json
import boto3
import hashlib
import os
import uuid
from datetime import datetime, timedelta

dynamodb = boto3.resource('dynamodb')
cognito = boto3.client('cognito-idp')
sns = boto3.client('sns')

def lambda_handler(event, context):
    print(f"Auth event: {json.dumps(event)}")
    
    try:
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
        
        auth_step = body.get('step', 1)
        
        if auth_step == 1:
            return handle_cognito_auth(body)
        elif auth_step == 2:
            return handle_security_question(body)
        elif auth_step == 3:
            return handle_caesar_cipher(body)
        else:
            return response_with_cors(400, {'error': 'Invalid authentication step. Must be 1, 2, or 3'})
            
    except Exception as e:
        print(f"Auth error: {str(e)}")
        return response_with_cors(500, {'error': 'Internal server error'})

def handle_cognito_auth(body):
    username = body.get('username', '').strip().lower()
    password = body.get('password', '')
    
    if not username or not password:
        return response_with_cors(400, {'error': 'Username and password are required'})
    
    try:
        users_table = dynamodb.Table(os.environ['USERS_TABLE'])
        user_response = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': username}
        )
        
        if not user_response['Items']:
            return response_with_cors(404, {'error': 'User not found in database'})
        
        user_data = user_response['Items'][0]
        user_id = user_data['userId']
        
        if not user_data.get('isActive', False):
            return response_with_cors(401, {'error': 'User account is inactive'})
        
        if user_data.get('verificationStatus') != 'verified':
            return response_with_cors(401, {'error': 'Email not verified. Please verify your email first.'})
        
        response = cognito.initiate_auth(
            ClientId=os.environ['COGNITO_CLIENT_ID'],
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        
        security_table = dynamodb.Table(os.environ['SECURITY_QUESTIONS_TABLE'])
        security_response = security_table.get_item(Key={'userId': user_id})
        
        if 'Item' not in security_response:
            return response_with_cors(404, {'error': 'Security question not found'})
        
        session_id = str(uuid.uuid4())
        sessions_table = dynamodb.Table(os.environ['USER_SESSIONS_TABLE'])
        sessions_table.put_item(
            Item={
                'sessionId': session_id,
                'userId': user_id,
                'authStep': 1,
                'createdAt': datetime.now().isoformat(),
                'expiresAt': int((datetime.now() + timedelta(minutes=10)).timestamp()),
                'cognitoTokens': {
                    'accessToken': response['AuthenticationResult']['AccessToken'],
                    'idToken': response['AuthenticationResult']['IdToken'],
                    'refreshToken': response['AuthenticationResult']['RefreshToken']
                }
            }
        )
        
        print(f"Step 1 authentication successful for user: {user_id}")
        
        return response_with_cors(200, {
            'message': 'First factor authentication successful',
            'nextStep': 2,
            'sessionId': session_id,
            'userId': user_id,
            'securityQuestion': security_response['Item']['securityQuestion']
        })
        
    except cognito.exceptions.NotAuthorizedException:
        return response_with_cors(401, {'error': 'Invalid username or password'})
    except cognito.exceptions.UserNotConfirmedException:
        return response_with_cors(401, {'error': 'User account not confirmed. Please verify your email first.'})
    except Exception as e:
        print(f"Cognito auth error: {str(e)}")
        return response_with_cors(401, {'error': 'Authentication failed'})

def handle_security_question(body):
    session_id = body.get('sessionId', '')
    user_id = body.get('userId', '')
    provided_answer = body.get('securityAnswer', '').strip()
    
    if not all([session_id, user_id, provided_answer]):
        return response_with_cors(400, {'error': 'Session ID, User ID, and security answer are required'})
    
    sessions_table = dynamodb.Table(os.environ['USER_SESSIONS_TABLE'])
    session_response = sessions_table.get_item(Key={'sessionId': session_id})
    
    if 'Item' not in session_response:
        return response_with_cors(401, {'error': 'Invalid or expired session'})
    
    session_data = session_response['Item']
    if session_data['userId'] != user_id or session_data['authStep'] != 1:
        return response_with_cors(401, {'error': 'Invalid session state'})
    
    security_table = dynamodb.Table(os.environ['SECURITY_QUESTIONS_TABLE'])
    security_response = security_table.get_item(Key={'userId': user_id})
    
    if 'Item' not in security_response:
        return response_with_cors(404, {'error': 'User security data not found'})
    
    stored_answer = security_response['Item']['securityAnswer']
    hashed_answer = hashlib.sha256(provided_answer.lower().strip().encode()).hexdigest()
    
    if hashed_answer == stored_answer:
        sessions_table.update_item(
            Key={'sessionId': session_id},
            UpdateExpression='SET authStep = :step',
            ExpressionAttributeValues={':step': 2}
        )
        
        caesar_challenge = security_response['Item']['caesarChallenge']
        
        print(f"Step 2 authentication successful for user: {user_id}")
        
        return response_with_cors(200, {
            'message': 'Second factor authentication successful',
            'nextStep': 3,
            'sessionId': session_id,
            'userId': user_id,
            'caesarChallenge': caesar_challenge['hint'],
            'caesarInstructions': caesar_challenge['instructions']
        })
    else:
        return response_with_cors(401, {'error': 'Incorrect security answer'})

def handle_caesar_cipher(body):
    session_id = body.get('sessionId', '')
    user_id = body.get('userId', '')
    provided_answer = body.get('caesarAnswer', '').upper().strip()
    
    if not all([session_id, user_id, provided_answer]):
        return response_with_cors(400, {'error': 'Session ID, User ID, and Caesar answer are required'})
    
    sessions_table = dynamodb.Table(os.environ['USER_SESSIONS_TABLE'])
    session_response = sessions_table.get_item(Key={'sessionId': session_id})
    
    if 'Item' not in session_response:
        return response_with_cors(401, {'error': 'Invalid or expired session'})
    
    session_data = session_response['Item']
    if session_data['userId'] != user_id or session_data['authStep'] != 2:
        return response_with_cors(401, {'error': 'Invalid session state'})
    
    security_table = dynamodb.Table(os.environ['SECURITY_QUESTIONS_TABLE'])
    security_response = security_table.get_item(Key={'userId': user_id})
    
    if 'Item' not in security_response:
        return response_with_cors(404, {'error': 'User security data not found'})
    
    correct_answer = security_response['Item']['caesarChallenge']['originalWord']
    
    if provided_answer == correct_answer:
        sessions_table.update_item(
            Key={'sessionId': session_id},
            UpdateExpression='SET authStep = :step, completedAt = :completed',
            ExpressionAttributeValues={
                ':step': 3,
                ':completed': datetime.now().isoformat()
            }
        )
        
        users_table = dynamodb.Table(os.environ['USERS_TABLE'])
        user_response = users_table.get_item(Key={'userId': user_id})
        user_data = user_response['Item']
        
        send_login_notification(user_data)
        
        print(f"Step 3 authentication successful for user: {user_id}")
        
        return response_with_cors(200, {
            'message': 'Authentication successful - All factors verified',
            'authComplete': True,
            'sessionId': session_id,
            'userId': user_id,
            'userType': user_data['userType'],
            'email': user_data['email'],
            'accessToken': session_data['cognitoTokens']['accessToken']
        })
    else:
        return response_with_cors(401, {'error': f'Incorrect Caesar cipher answer. Expected: {correct_answer}'})

def send_login_notification(user_data):
    try:
        topic_arn = os.environ.get('LOGIN_TOPIC_ARN', '')
        if not topic_arn:
            print("No login topic ARN configured, skipping notification")
            return
        
        message = {
            'email': user_data['email'],
            'userId': user_data['userId'],
            'userType': user_data['userType'],
            'loginTime': datetime.now().isoformat(),
            'event': 'user_login'
        }
        
        sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message),
            Subject=f'DALScooter Login - {user_data["email"]}'
        )
        
        print(f"Login notification sent for user: {user_data['userId']}")
        
    except Exception as e:
        print(f"Error sending login notification: {str(e)}")

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