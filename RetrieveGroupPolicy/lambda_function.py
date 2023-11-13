import os
import boto3
import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode
import mysql.connector

# envs
AWS_REGION = os.environ['AWS_REGION']
COGNITO_USER_POOL_ID = os.environ['COGNITO_USER_POOL_ID']
COGNITO_APP_CLIENT_ID = os.environ['COGNITO_APP_CLIENT_ID']
COGNITO_APP_DEV_CLIENT_ID = os.environ['COGNITO_APP_DEV_CLIENT_ID']
host = os.getenv('DB_URI')
username = os.getenv('DB_USERNAME')
password = os.getenv('DB_PASSWORD')
database = os.getenv('DB_NAME')

keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(AWS_REGION, COGNITO_USER_POOL_ID)

# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

conn = mysql.connector.connect(
    host = host,
    database = database,
    user = username,
    password = password
)



def lambda_handler(event, context):
    print(f'Lambda Authorizer Event: {event}')
    print(f'Context: {context}')

    token_data = parse_token_data(event)
    if token_data['valid'] is False:
        return get_deny_policy()

    try:
        claims = validate_token(token_data['token'])
        groups = claims['cognito:groups']

        policy = generate_role_policy(groups[0], event['methodArn'].split('/')[0])

        print(f'Policy: {policy}')

        return policy

    except Exception as e:
        print(e)

    return get_deny_policy()

def get_deny_policy():
    return {
        "principalId": "yyyyyyyy",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": "arn:aws:execute-api:*:*:*/ANY/*"
                }
            ]
        },
        "context": {},
        "usageIdentifierKey": "{api-key}"
    }


def parse_token_data(event):
    response = {'valid': False}

    if 'authorizationToken' not in event:
        return response

    auth_header = event['authorizationToken']
    auth_header_list = auth_header.split(' ')

    # deny request of header isn't made out of two strings, or
    # first string isn't equal to "Bearer" (enforcing following standards,
    # but technically could be anything or could be left out completely)
    if len(auth_header_list) != 2 or auth_header_list[0] != 'Bearer':
        return response

    access_token = auth_header_list[1]
    return {
        'valid': True,
        'token': access_token
    }


def validate_token(token):
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']

    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break

    if key_index == -1:
        print('Public key not found in jwks.json')
        return False

    # construct the public key
    public_key = jwk.construct(keys[key_index])

    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)

    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False

    print('Signature successfully verified')

    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    print(f'Claims: {claims}')

    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False

    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['client_id'] not in [COGNITO_APP_CLIENT_ID, COGNITO_APP_DEV_CLIENT_ID]:
        print('Token was not issued for this audience')
        return False

    # now we can use the claims
    return claims


def generate_role_policy(role_id, gateway_arn):

    print(f"Role ID: {role_id}")
    print(f"Gateway ARN: {gateway_arn}")
    # Query all role access rights from DB
    cursor = conn.cursor(dictionary=True)
    cursor.execute(f"select ap.endpoint from role_access ra join access_points ap on ra.ap_id = ap.id where role_id = {role_id}")
    endpoints = cursor.fetchall()
    conn.commit()
    print(f"Access List: {endpoints}")

    # Generate access list
    access_list = []

    for endpoint in endpoints:
        print(f"Endpoint: {endpoint}")
        access_list.append(f"{gateway_arn}{endpoint['endpoint']}")

    print(f"Access List: {access_list}")

    if len(access_list) == 0:
        return get_deny_policy()
    else:
        return {
            "principalId": "yyyyyyyy",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "execute-api:Invoke",
                        "Resource": access_list
                    }
                ]
            },
            "context": {},
            "usageIdentifierKey": "{api-key}"
        }