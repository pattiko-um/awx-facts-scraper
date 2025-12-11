import requests
from requests.auth import HTTPBasicAuth
import json

API_ROOT="https://awx.lsait.lsa.umich.edu/api/v2/"

def api_fetch(endpoint):
  # Load credentials from environment variables (recommended)
  import os
  username = os.getenv("AWX_USER")
  password = os.getenv("AWX_PASS")

  try:
    response = requests.get(API_ROOT + endpoint, auth=HTTPBasicAuth(username, password))
    print("Status:", response.status_code)

    return response.json()

  except Exception as e:
    print("Error fetching data:", e)

def process_host(raw_host_data):
  host_id = raw_host_data['id']
  
  host_variables = json.loads(raw_host_data.get('variables', ''))
  host_facts = api_fetch(f"hosts/{host_id}/ansible_facts/")
  host_facts_local = host_facts.get("ansible_local", {})

  host = {
    "awx_id": host_id,
    "support_group": host_variables.get("foreman_location_name", "Unassigned"),
		"hostname": host_facts.get("lsa_host", {}).get("hostname", "Unknown"),
    "os": host_facts_local.get("lsa_host", {}).get("os", {}).get("tdx_friendly", "Unknown"),
    "host_collection": "Placeholder",
    "password_rotation": "Placeholder",
    "duo": "Placeholder",
    "ldap": "Placeholder",
    "ad_bind": host_facts_local.get("lsa_ad_bind", {}).get("state", None) == "installed",
    "firewalld": host_facts_local.get("lsa_firewalld_dev_base", {}).get("state", None) == "installed",
    "threatdown": host_facts_local.get("mwalwarebytes", {}).get("state", None) == "installed",
    "crowdstrike": host_facts_local.get("lsa_falcon_sensor", {}).get("state", None) == "installed",
    "tenable": host_facts_local.get("NessusAgent_10_8_2", {}).get("state", None) == "installed",
    "ubuntu_pro": host_facts_local.get("ubuntu_pro", {}).get("attached", None)
  }

  return host

def convert_to_csv(data, filename="output.csv"):
  import csv

  if not data:
    print("No data to write.")
    return

  keys = data[0].keys()
  with open(filename, 'w', newline='') as output_file:
    dict_writer = csv.DictWriter(output_file, fieldnames=keys)
    dict_writer.writeheader()
    dict_writer.writerows(data)
  print(f"Data written to {filename}")

if __name__ == "__main__":
  hosts = []
  
  fetched_data = api_fetch("hosts?page_size=200")

  raw_hosts_list = fetched_data.get("results", [])

  for raw_host in raw_hosts_list:
    processed_host = process_host(raw_host)
    hosts.append(processed_host)
  
  convert_to_csv(hosts)