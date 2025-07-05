import json
import boto3
import os

cognito = boto3.client('cognito-idp')

def lambda_handler(event, context):
    print(f"Resend verification event: {json.dumps(event)}")
    
    try:
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
        
        email = body.get('email', '').strip().lower()
        
        if not email:
            return response_with_cors(400, {'error': 'Email is required'})
        
        try:
            cognito.resend_confirmation_code(
                ClientId=os.environ['COGNITO_CLIENT_ID'],
                Username=email
            )
            
            print(f"Verification code resent for: {email}")
            
            return response_with_cors(200, {
                'message': 'Verification code sent to your email address.'
            })
            
        except cognito.exceptions.InvalidParameterException:
            return response_with_cors(400, {'error': 'User not found or already verified'})
        except Exception as e:
            print(f"Resend error: {str(e)}")
            return response_with_cors(400, {'error': 'Failed to resend verification code'})
            
    except Exception as e:
        print(f"Resend verification error: {str(e)}")
        return response_with_cors(500, {'error': 'Internal server error'})

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