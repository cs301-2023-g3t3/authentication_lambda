import psycopg2
from psycopg2.extras import RealDictCursor
import os

host = os.getenv('DB_URI')
username = os.getenv('DB_USERNAME')
password = os.getenv('DB_PASSWORD')
database = os.getenv('DB_NAME')

conn = psycopg2.connect(
    host = host,
    database = database,
    user = username,
    password = password
)

def lambda_handler(event, context):

    # Set autoconfirm to false until validated
    event['response']['autoConfirmUser'] = False
    
    # Validate if user is in RDS User Table
    email = event['request']['userAttributes']['email']

    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(f"select * from users where email = '{email}' limit 1")
    results = cursor.fetchone()
    if results:

        user_obj = dict(results)

        if user_obj['role'] != None:
            event['response']['autoConfirmUser'] = True
    
    if not event['response']['autoConfirmUser']:
        raise Exception("Invalid User detected!")

    return event
