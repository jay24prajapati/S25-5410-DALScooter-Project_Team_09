import boto3
import time
import json
import traceback

athena_client = boto3.client('athena')

def lambda_handler(event, context):
    try:       
        users_table = f"DALScooter-Users-dev"

        queries = [
            {
                "key": "active_users",
                "query": f"""
                SELECT usertype as user_type,
                       isactive as is_active,
                       COUNT(*) as user_count
                FROM "{users_table}"
                GROUP BY usertype, isactive;
                """
            },
            {
                "key": "verification_completion_rate",
                "query": f"""
                SELECT usertype as user_type,
                       COUNT(CASE WHEN verificationstatus = 'verified' THEN 1 END) * 100.0 / COUNT(*) as verification_rate
                FROM "{users_table}"
                GROUP BY usertype;
                """
            }
        ]

        database = 'default'
        output_location = 's3://dalscooter-athena-results/results/'
        results = {}
        
        for q in queries:
            print(f"Executing query: {q['key']} for table {users_table} in catalog 'dalscooter', database '{database}'")
            print(f"Query: {q['query']}")
            response = athena_client.start_query_execution(
                QueryString=q["query"],
                QueryExecutionContext={'Database': database, 'Catalog': 'dalscooter'},
                ResultConfiguration={'OutputLocation': output_location}
            )
            query_execution_id = response['QueryExecutionId']
            
            max_attempts = 40
            attempt = 0
            while attempt < max_attempts:
                query_status = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
                status = query_status['QueryExecution']['Status']['State']
                if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                    break
                time.sleep(0.5)
                attempt += 1

            if status != 'SUCCEEDED':
                error_message = query_status['QueryExecution']['Status'].get('StateChangeReason', 'No detailed error message provided')
                print(f"Query {q['key']} failed with status {status}: {error_message}")
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': f'Athena query {q["key"]} failed with status {status}',
                        'details': error_message
                    }),
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                }
            
            query_results = athena_client.get_query_results(QueryExecutionId=query_execution_id)
            rows = query_results['ResultSet']['Rows']
            headers = [col['VarCharValue'] for col in rows[0]['Data']]
            data = []
            for row in rows[1:]:
                row_data = {}
                for i, cell in enumerate(row['Data']):
                    row_data[headers[i]] = cell.get('VarCharValue', '')
                data.append(row_data)
            results[q["key"]] = data
        
        return {
            'statusCode': 200,
            'body': json.dumps(results),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }
    except Exception as e:
        print("Exception occurred:", traceback.format_exc())
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)}),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }