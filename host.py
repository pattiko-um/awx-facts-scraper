import json
import re
import awx
from patch_groups import PATCH_CYCLE_GROUPS

class Host:
  SOFTWARE_MAP = {
    "ad_bind": "lsa_ad_bind",
    "firewalld": "lsa_firewalld_dev_base",
    "threatdown": "mwalwarebytes",
    "crowdstrike": "lsa_falcon_sensor",
    "tenable": "NessusAgent"
  }

  # ordered fields for CSV export; software flags are expanded from SOFTWARE_MAP
  FIELDS = [
    ("awx_id", None),
    ("support_group", None),
    ("hostname", None),
    ("os", None),
    ("host_collection", None),
    ("password_rotation", None),
    ("duo", None),
    ("ldap", None),
  ]

  CSV_FIELDS = [name for name, _ in FIELDS] + list(SOFTWARE_MAP.keys()) + ["ubuntu_pro"]

  def __init__(self, raw_data):
    self.raw_data = raw_data
  
    # always set identifying attributes
    self.awx_id = raw_data['id']

    # load variables safely, treating unparseable strings like '---' as empty
    try:
      variables_str = raw_data.get('variables') or '{}'
      self.variables = json.loads(variables_str)
    except (json.JSONDecodeError, ValueError):
      self.variables = {}

    self.raw_facts = awx.get_host_facts(self.awx_id)
    self.raw_facts_local = self.raw_facts.get("ansible_local", {})
    self.groups = self.raw_data.get("summary_fields", {}).get("groups", {}).get("results", [])

    # initialize canonical defaults for known fields and software
    for name, default in self.FIELDS:
      if not hasattr(self, name):
        setattr(self, name, default)

    # initialize software flags to None
    for key in self.SOFTWARE_MAP:
      if not hasattr(self, key):
        setattr(self, key, None)

    # ubuntu_pro default
    if not hasattr(self, 'ubuntu_pro'):
      self.ubuntu_pro = None

    self.support_group = self.variables.get("foreman_location_name", "Self-Managed")
    self.set_hostname()
    self.set_os()
    self.set_host_collection()
    self.set_password_rotation()
    self.ubuntu_pro = self.raw_facts_local.get("ubuntu_pro", {}).get("attached", None)
    self.duo = "Placeholder"
    self.ldap = "Placeholder"

    # set software installation flags
    # Try exact key first, otherwise find a key that contains the fact_key string
    for attr, fact_key in self.SOFTWARE_MAP.items():
      matched_key = None
      # exact match
      if fact_key in self.raw_facts_local:
        matched_key = fact_key
      else:
        # fallback: find a key that contains the fact_key as a substring
        for k in self.raw_facts_local.keys():
          if re.search(re.escape(fact_key), k):
            matched_key = k
            break

      value = None
      if matched_key is not None:
        value = self.raw_facts_local.get(matched_key, {}).get("state") == "installed"
      setattr(self, attr, value)

  def set_hostname(self):
    facts_hostname = (self.raw_facts_local
                      .get("lsa_host", {})
                      .get("hostname", None))
    self.hostname = facts_hostname or self.raw_data["name"]

  def set_os(self):
    # Picks most useful OS name from variables and facts
    # Note: Can improve facts_os with minor version if necessary
    facts_os = (self.raw_facts_local
                .get("lsa_host", {})
                .get("os", {})
                .get("tdx_friendly", "")
                .removeprefix("Linux: "))
    variables_os = (self.variables
                    .get("foreman_content_facet_attributes", {})
                    .get("content_view", {})
                    .get("name", None))
    self.os = self.variables.get("foreman_operatingsystem_name", None) or variables_os or facts_os or "Unknown"
  
  def set_host_collection(self):
    # Returns True if any group name matches a whitelisted patch cycle group
    self.host_collection = any(
      group["name"] in PATCH_CYCLE_GROUPS
      for group in self.groups
    )
  
  def set_password_rotation(self):
    # Returns True if any group name contains "password_rotation"
    self.password_rotation = any(
      "password_rotation" in group.get("name", "")
      for group in self.groups
    )

  def to_dict(self):
    out = {}
    for key in self.CSV_FIELDS:
      out[key] = getattr(self, key, None)
    return out