import requests
import zipfile
import xml.etree.ElementTree as ET
import io
import os
import boto3
import re  # <-- Importing the regex module to strip namespace


from counterspell_auth.credentials import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

print("AWS Access Key ID:", AWS_ACCESS_KEY_ID)
print("AWS Secret Access Key:", AWS_SECRET_ACCESS_KEY)

# Download the ZIP file
zip_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
response = requests.get(zip_url)

s3 = boto3.client('s3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name='us-east-2')
s3_bucket_name = 'counterspell-raw'

# Function to strip namespace from tag names
def strip_namespace(tag):
    return re.sub(r'\{.*\}', '', tag)  # <-- Removes the namespace prefix from the tag name

# Check if the request was successful
if response.status_code == 200:
    # Open the zip file
    with zipfile.ZipFile(io.BytesIO(response.content), 'r') as zip_ref:
        # Extract the contents
        zip_ref.extractall("cwec_xml")

    # After extracting the XML content
    xml_files = [file for file in os.listdir("cwec_xml") if file.endswith('.xml')]

    # Iterate over each XML file
    for xml_file in xml_files:
        xml_file_path = os.path.join("cwec_xml", xml_file)
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # Strip namespaces from all elements
        for elem in root.iter():
            elem.tag = strip_namespace(elem.tag)  # <-- Applying the namespace stripping function


        count = 0

        # Extract each Weakness and send it to S3
        for weakness in root.findall(".//Weakness"):
            # Now this should find the correct elements without namespace issues
            weakness_id = weakness.attrib['ID']
            output_key = f"cwe/CWE-{weakness_id}.xml"

            # Serialize XML content without namespace issues
            xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
            xml_content += ET.tostring(weakness, encoding='unicode')  # <-- This should produce clean XML without "ns0"

            # Upload to S3
            s3.put_object(Body=xml_content, Bucket=s3_bucket_name, Key=output_key)

            count += 1

            print(f"Uploaded Weakness {weakness_id} to s3://{output_key}")
        print(f'Uploaded {count} weaknesses')

else:
    print("Failed to download the file")
