# This script fetches all results using pagination. This may have a issue with memory
import requests
import json
import time

def fetch_cve_list(start_index, results_per_page=20):
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

def fetch_all_cves(results_per_page=2000): # 2000 max per page
    all_cves = []

    # Start fetching CVEs from index 0
    start_index = 0

    while True:
        print(start_index)
        cves = fetch_cve_list(start_index, results_per_page)

        if not cves:
            break  # Stop if there's an error fetching CVEs

        all_cves.extend(cves)

        # Update start_index for the next batch
        start_index += results_per_page

        # Check if there are more CVEs to fetch
        if start_index >= 4000: # change logic to get all results !!!
            print('condition met')
            break

        time.sleep(10)

    return all_cves

if __name__ == "__main__":
    all_cves = fetch_all_cves()
    
    if all_cves:
        print(f"Total CVEs fetched: {len(all_cves)}")
        # print(all_cves)
        
        # Print and format the fetched JSON data
        formatted_json = json.dumps(all_cves, indent=2)
        
        with open('output.json', 'w') as f:
            f.write(formatted_json)

        # Process or display the fetched CVEs as needed
    else:
        print("Failed to fetch CVEs.")
