import json
import boto3
import os

dynamodb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    print(f"Security question event: {json.dumps(event)}")
    
    try:
        user_id = event.get('pathParameters', {}).get('userId')
        
        if not user_id:
            return response_with_cors(400, {'error': 'User ID is required in the URL path'})
        
        users_table = dynamodb.Table(os.environ['USERS_TABLE'])
        user_response = users_table.get_item(Key={'userId': user_id})
        
        if 'Item' not in user_response:
            return response_with_cors(404, {'error': 'User not found'})
        
        security_table = dynamodb.Table(os.environ['SECURITY_QUESTIONS_TABLE'])
        security_response = security_table.get_item(Key={'userId': user_id})
        
        if 'Item' not in security_response:
            return response_with_cors(404, {'error': 'Security question not found for this user'})
        
        user_data = user_response['Item']
        security_data = security_response['Item']
        
        return response_with_cors(200, {
            'userId': user_id,
            'securityQuestion': security_data['securityQuestion'],
            'email': user_data['email'],
            'userType': user_data['userType']
        })
        
    except Exception as e:
        print(f"Security question error: {str(e)}")
        return response_with_cors(500, {'error': 'Internal server error'})

def response_with_cors(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,OPTIONS',
            'Content-Type': 'application/json'
        },
        'body': json.dumps(body)
    }