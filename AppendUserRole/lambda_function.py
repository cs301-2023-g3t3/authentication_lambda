import mysql.connector
import os

host = os.getenv('DB_URI')
username = os.getenv('DB_USERNAME')
password = os.getenv('DB_PASSWORD')
database = os.getenv('DB_NAME')

conn = mysql.connector.connect(
    host = host,
    database = database,
    user = username,
    password = password
)

def lambda_handler(event, context):
    
    # Validate if user is in RDS User Table
    email = event['request']['userAttributes']['email']

    cursor = conn.cursor(dictionary=True)
    cursor.execute(f"select * from users where email = '{email}' limit 1")
    results = cursor.fetchone()

    if results:

        user_obj = dict(results)
        user_role = user_obj['role']

        print(f'User Role: {user_role}')

        if user_role == None:
            raise Exception("Access Denied!")
        else:
            event["response"]["claimsOverrideDetails"] = { 
                "claimsToAddOrOverride": { 
                    "role": user_role,
                },
                "groupOverrideDetails": {
                    "groupsToOverride": [
                        user_role
                    ]
                }
            }

    else:
        raise Exception("User not found!")


    return event
