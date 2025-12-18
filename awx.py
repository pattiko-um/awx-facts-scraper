import urllib.request
import urllib.error
import base64
import json
import os
from host import Host

API_ROOT="https://awx.lsait.lsa.umich.edu/api/v2"
AWX_USER = os.getenv("AWX_USER")
AWX_PASS = os.getenv("AWX_PASS")

def fetch(endpoint):
  try:
    url = API_ROOT + endpoint
    credentials = base64.b64encode(f"{AWX_USER}:{AWX_PASS}".encode()).decode()
    
    req = urllib.request.Request(url)
    req.add_header('Authorization', f'Basic {credentials}')
    
    with urllib.request.urlopen(req) as response:
      print("Get:", endpoint, "Status:", response.status)
      return json.loads(response.read().decode())

  except urllib.error.URLError as e:
    print("Error fetching data:", e)
  except Exception as e:
    print("Error fetching data:", e)

def get_hosts(page_size=10):
  hosts = []
  endpoint = f"/hosts?page_size={page_size}"

  fetched_data = fetch(endpoint)
  raw_hosts_list = fetched_data.get("results", [])

  for raw_host in raw_hosts_list:
    new_host = Host(raw_host)
    hosts.append(new_host)

  return hosts

def get_host_facts(host_id):
  endpoint = f"/hosts/{host_id}/ansible_facts/"

  return fetch(endpoint)

def get_groups(page_size=10):
  groups = []
  endpoint = f"/groups?page_size={page_size}"

  fetched_data = fetch(endpoint)
  raw_groups_list = fetched_data.get("results", [])

  for raw_group in raw_groups_list:
    new_group = {
      "id": raw_group["id"],
      "name": raw_group["name"],
      "description": raw_group["description"],
      "inventory_name": (raw_group.get("summary_fields", {})
                         .get("inventory", {})
                         .get("name", None))
    }
    groups.append(new_group)

  return groups