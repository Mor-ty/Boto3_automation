import boto3
import json
from datetime import datetime, timezone

iam = boto3.client('iam')
findings = []
users = iam.list_users()['Users']
print(users)