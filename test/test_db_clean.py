import boto3
from boto3.dynamodb.conditions import Key
import json
from decimal import Decimal


# Initialize DynamoDB client
dynamodb = boto3.resource(
    'dynamodb',
    region_name='us-east-2',
    aws_access_key_id='REDACTED',
    aws_secret_access_key='REDACTED'
)
table = dynamodb.Table('counterspell-cve')

# Extracted data
cves = []

for cve in cves:

  selected_fields = {
      "id": cve["cve"]["id"],
      "published": cve["cve"]["published"],
      "lastModified": cve["cve"]["lastModified"],
      "vulnStatus": cve["cve"]["vulnStatus"],
      "description": [desc["value"] for desc in cve["cve"]["descriptions"] if desc["lang"] == "en"][0],
      "metrics": json.loads(json.dumps(cve["cve"]["metrics"]), parse_float=Decimal),
      "weaknesses": [desc["value"] for weakness in cve["cve"]["weaknesses"] for desc in weakness["description"] if desc["lang"] == "en"]
  }

  print('put')
  print(selected_fields)
  table.put_item(Item=selected_fields)
