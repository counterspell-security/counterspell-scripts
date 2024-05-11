import requests
import json
import time
import multiprocessing
import boto3
from boto3.dynamodb.conditions import Key
from counterspell_auth.credentials import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

print("AWS Access Key ID:", AWS_ACCESS_KEY_ID)
print("AWS Secret Access Key:", AWS_SECRET_ACCESS_KEY)

# Initialize s3 client
s3 = boto3.client('s3',
                  aws_access_key_id=AWS_ACCESS_KEY_ID,
                  aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                  region_name='us-east-2')
s3_bucket_name = 'counterspell-raw'

def output_to_db(cves, counter, lock):
    # iterate through cves
    for cve in cves:
        id = cve["cve"]["id"]
        object_key = 'cve/'+id

        # Convert the JSON data to a string
        json_string = json.dumps(cve)

        # Upload the JSON string as an object to S3
        s3.put_object(
            Bucket=s3_bucket_name,
            Key=object_key,
            Body=json_string.encode('utf-8'),
            ContentType='application/json'
        )

        # Increment counter
        with lock:
            counter.value += 1

        print(f"JSON data uploaded to S3://{s3_bucket_name}/{object_key}")

def fetch_cve_list(start_index, results_per_page=2000):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }

    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()  # Check for HTTP errors

        cve_data = response.json()
        vulnerabilities = cve_data.get("vulnerabilities", [])

        return vulnerabilities

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE data: {e}")
        return None

def fetch_cves(start_index, finish_index, results_per_page, counter, lock):
    # Start fetching CVEs from index 0
    i = start_index

    while i < finish_index:
        print(f'i = {i}')
        cves = fetch_cve_list(i, results_per_page)

        if not cves:
            break

        output_to_db(cves, counter, lock)

        # Update start_index for the next batch
        i += results_per_page

def main():
    total_cves = 250000
    num_processes = 10
    results_per_page = 2000
    counter = multiprocessing.Value('i', 0)
    lock = multiprocessing.Lock()

    processes = []
    batch_size = total_cves // num_processes

    for i in range(num_processes):
        start_index = i * batch_size
        end_index = min(start_index + batch_size, total_cves)
        p = multiprocessing.Process(target=fetch_cves, args=(start_index, end_index, results_per_page, counter, lock))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    if counter.value != 0:
        print(f"Total CVEs fetched: {counter.value}")
    else:
        print("Failed to fetch CVEs.")

if __name__ == "__main__":
    start = time.time()
    open('output.json', 'w').close()  # reset file
    main()
    end = time.time()
    print(f"Process took {end - start} seconds")
