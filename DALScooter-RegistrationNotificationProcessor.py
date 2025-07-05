import json
import boto3
import uuid
import os
from datetime import datetime, timedelta

dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

def lambda_handler(event, context):
    print(f"Processing registration notifications: {json.dumps(event)}")
    
    processed_count = 0
    failed_count = 0
    
    for record in event.get('Records', []):
        try:
            message_body = json.loads(record['body'])
            
            if 'Message' in message_body:
                actual_message = json.loads(message_body['Message'])
                message_attributes = message_body.get('MessageAttributes', {})
            else:
                actual_message = message_body
                message_attributes = {}
            
            notification_id = process_registration_notification(actual_message, message_attributes)
            processed_count += 1
            
            print(f"Successfully processed registration notification: {notification_id}")
            
        except Exception as e:
            print(f"Error processing record: {str(e)}")
            failed_count += 1
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'processed': processed_count,
            'failed': failed_count,
            'message': 'Registration notifications processed'
        })
    }

def process_registration_notification(message, attributes):
    notification_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    email = message.get('email', 'unknown@gmail.com')
    user_id = message.get('userId', 'unknown')
    user_type = message.get('userType', 'unknown')
    event_type = message.get('event', 'user_registered')
    
    # Log notification
    log_notification(
        notification_id=notification_id,
        timestamp=timestamp,
        notification_type='registration',
        user_id=user_id,
        email=email,
        event_type=event_type,
        message_data=message,
        status='processing'
    )
    
    try:
        print(f"   REGISTRATION NOTIFICATION SENT:")
        print(f"   Email: {email}")
        print(f"   User ID: {user_id}")
        print(f"   User Type: {user_type}")
        print(f"   Welcome message would be sent here")
        
        # Update status to sent
        update_notification_status(notification_id, timestamp, 'sent')
        print(f"Registration notification processed for user: {user_id}")
        
    except Exception as e:
        print(f"Failed to send registration notification: {str(e)}")
        update_notification_status(notification_id, timestamp, 'failed', str(e))
        raise
    
    return notification_id

def log_notification(notification_id, timestamp, notification_type, user_id, email, event_type, message_data, status, error_message=None):
    table = dynamodb.Table(os.environ['NOTIFICATION_LOGS_TABLE'])
    
    ttl = int((datetime.now() + timedelta(days=90)).timestamp())
    
    item = {
        'notificationId': notification_id,
        'timestamp': timestamp,
        'notificationType': notification_type,
        'userId': user_id,
        'recipientEmail': email,
        'eventType': event_type,
        'status': status,
        'messageData': json.dumps(message_data, default=str),
        'createdAt': timestamp,
        'ttl': ttl
    }
    
    if error_message:
        item['errorMessage'] = error_message
        item['errorTimestamp'] = datetime.now().isoformat()
    
    table.put_item(Item=item)

def update_notification_status(notification_id, timestamp, status, error_message=None):
    table = dynamodb.Table(os.environ['NOTIFICATION_LOGS_TABLE'])
    
    update_expression = 'SET #status = :status, updatedAt = :updated_at'
    expression_values = {
        ':status': status,
        ':updated_at': datetime.now().isoformat()
    }
    expression_names = {
        '#status': 'status'
    }
    
    if error_message:
        update_expression += ', errorMessage = :error_message, errorTimestamp = :error_timestamp'
        expression_values[':error_message'] = error_message
        expression_values[':error_timestamp'] = datetime.now().isoformat()
    
    table.update_item(
        Key={
            'notificationId': notification_id,
            'timestamp': timestamp
        },
        UpdateExpression=update_expression,
        ExpressionAttributeValues=expression_values,
        ExpressionAttributeNames=expression_names
    )