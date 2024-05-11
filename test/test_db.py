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
cves = {
    "cve": {
      "id": "CVE-1999-0095",
      "sourceIdentifier": "cve@mitre.org",
      "published": "1988-10-01T04:00:00.000",
      "lastModified": "2019-06-11T20:29:00.263",
      "vulnStatus": "Modified",
      "descriptions": [
        {
          "lang": "en",
          "value": "The debug command in Sendmail is enabled, allowing attackers to execute commands as root."
        },
        {
          "lang": "es",
          "value": "El comando de depuraci\u00f3n de Sendmail est\u00e1 activado, permitiendo a atacantes ejecutar comandos como root."
        }
      ],
      "metrics": {
        "cvssMetricV2": [
          {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {
              "version": "2.0",
              "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
              "accessVector": "NETWORK",
              "accessComplexity": "LOW",
              "authentication": "NONE",
              "confidentialityImpact": "COMPLETE",
              "integrityImpact": "COMPLETE",
              "availabilityImpact": "COMPLETE",
              "baseScore": 10.0
            },
            "baseSeverity": "HIGH",
            "exploitabilityScore": 10.0,
            "impactScore": 10.0,
            "acInsufInfo": False,
            "obtainAllPrivilege": True,
            "obtainUserPrivilege": False,
            "obtainOtherPrivilege": False,
            "userInteractionRequired": False
          }
        ]
      },
      "weaknesses": [
        {
          "source": "nvd@nist.gov",
          "type": "Primary",
          "description": [
            {
              "lang": "en",
              "value": "NVD-CWE-Other"
            },
            {
              "lang": "es",
              "value": "NVD-CWE-000"
            }
          ]
        },
        {
          "source": "nvd@nist.gov",
          "type": "Primary",
          "description": [
            {
              "lang": "es",
              "value": "NVD-CWE-000"
            },
            {
              "lang": "en",
              "value": "NVD-CWE-123"
            }
          ]
        }
      ],
      "configurations": [
        {
          "nodes": [
            {
              "operator": "OR",
              "negate": False,
              "cpeMatch": [
                {
                  "vulnerable": True,
                  "criteria": "cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*",
                  "matchCriteriaId": "1D07F493-9C8D-44A4-8652-F28B46CBA27C"
                }
              ]
            }
          ]
        }
      ],
      "references": [
        {
          "url": "http://seclists.org/fulldisclosure/2019/Jun/16",
          "source": "cve@mitre.org"
        },
        {
          "url": "http://www.openwall.com/lists/oss-security/2019/06/05/4",
          "source": "cve@mitre.org"
        },
        {
          "url": "http://www.openwall.com/lists/oss-security/2019/06/06/1",
          "source": "cve@mitre.org"
        },
        {
          "url": "http://www.osvdb.org/195",
          "source": "cve@mitre.org"
        },
        {
          "url": "http://www.securityfocus.com/bid/1",
          "source": "cve@mitre.org"
        }
      ]
    }
}

# process weaknesses. convert this into one liner
# tmp = []
# for weakness in cves["cve"]["weaknesses"]:
#     for desc in weakness["description"]:
#         if desc["lang"] == "en":
#             tmp.append(desc["value"])
# print(tmp)


# change code here to add selected_fields
selected_fields = {
    "id": cves["cve"]["id"],
    "published": cves["cve"]["published"],
    "lastModified": cves["cve"]["lastModified"],
    "vulnStatus": cves["cve"]["vulnStatus"],
    "description": [desc["value"] for desc in cves["cve"]["descriptions"] if desc["lang"] == "en"][0],
    "metrics": json.loads(json.dumps(cves["cve"]["metrics"]), parse_float=Decimal),
    "weaknesses": [desc["value"] for weakness in cves["cve"]["weaknesses"] for desc in weakness["description"] if desc["lang"] == "en"]
}

print('put')
print(selected_fields)
table.put_item(Item=selected_fields)
