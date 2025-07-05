import json
import boto3
import os
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
cognito = boto3.client('cognito-idp')

def lambda_handler(event, context):
    print(f"Email verification event: {json.dumps(event)}")
    
    try:
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
        
        email = body.get('email', '').strip().lower()
        verification_code = body.get('verificationCode', '').strip()
        
        if not email or not verification_code:
            return response_with_cors(400, {'error': 'Email and verification code are required'})
        
        try:
            cognito.confirm_sign_up(
                ClientId=os.environ['COGNITO_CLIENT_ID'],
                Username=email,
                ConfirmationCode=verification_code
            )
            
            user_id = get_user_id_by_email(email)
            if user_id:
                users_table = dynamodb.Table(os.environ['USERS_TABLE'])
                users_table.update_item(
                    Key={'userId': user_id},
                    UpdateExpression='SET verificationStatus = :status, verifiedAt = :verified_at',
                    ExpressionAttributeValues={
                        ':status': 'verified',
                        ':verified_at': datetime.now().isoformat()
                    }
                )
            
            print(f"Email verified successfully for: {email}")
            
            return response_with_cors(200, {
                'message': 'Email verified successfully! You can now login.',
                'verified': True
            })
            
        except cognito.exceptions.CodeMismatchException:
            return response_with_cors(400, {'error': 'Invalid verification code'})
        except cognito.exceptions.ExpiredCodeException:
            return response_with_cors(400, {'error': 'Verification code has expired'})
        except cognito.exceptions.NotAuthorizedException:
            return response_with_cors(400, {'error': 'User is already verified'})
        except Exception as e:
            print(f"Verification error: {str(e)}")
            return response_with_cors(400, {'error': 'Verification failed'})
            
    except Exception as e:
        print(f"Email verification error: {str(e)}")
        return response_with_cors(500, {'error': 'Internal server error'})

def get_user_id_by_email(email):
    try:
        users_table = dynamodb.Table(os.environ['USERS_TABLE'])
        response = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        
        if response['Items']:
            return response['Items'][0]['userId']
        return None
    except Exception as e:
        print(f"Error getting user ID: {str(e)}")
        return None

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