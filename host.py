import json
import re
import awx
from datetime import datetime
from patch_groups import PATCH_CYCLE_GROUPS

class Host:
  FIELDS = [
    ("awx_id", None),
    ("support_group", None),
    ("hostname", None),
    ("os", None),
    ("host_collection", None),
    ("password_rotation", None),
    ("duo", None),
    ("ldap", None),
    ("nessus", None),
    ("crowdstrike", None),
    ("threatdown", None),
    ("ad_bind", None),
    ("firewalld", None),
    ("ubuntu_pro", None),
    ("password_rotated_on", None)
  ]

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
    self.lsa_host = self.raw_facts_local.get("lsa_host", {})
    self.groups = self.raw_data.get("summary_fields", {}).get("groups", {}).get("results", [])

    # initialize canonical defaults for known fields and software
    for name, default in self.FIELDS:
      if not hasattr(self, name):
        setattr(self, name, default)

    self.support_group = self.variables.get("foreman_location_name", "Self-Managed")
    self.set_hostname()
    self.set_os()
    self.set_host_collection()
    self.set_password_rotation()
    self.set_duo()
    self.set_security_agents()
    self.set_software()
    self.ubuntu_pro = self.raw_facts_local.get("ubuntu_pro", {}).get("attached", None)
    self.ldap = None  # Placeholder for future LDAP logic

  def set_hostname(self):
    self.hostname = self.raw_data["name"].split(".")[0]

  def set_os(self):
    # Picks most useful OS name from variables and facts
    # Note: Can improve facts_os with minor version if necessary
    facts_os = (self.lsa_host
                .get("os", {})
                .get("tdx_friendly", "")
                .removeprefix("Linux: "))

    foreman_content_attrs = self.variables.get("foreman_content_facet_attributes") or {}
    content_view = foreman_content_attrs.get("content_view") or {}
    variables_os = content_view.get("name", "")

    self.os = self.variables.get("foreman_operatingsystem_name", None) or variables_os or facts_os or "Unknown"
  
  def set_host_collection(self):
    # Returns True if any group name matches a whitelisted patch cycle group
    self.host_collection = any(
      group["name"] in PATCH_CYCLE_GROUPS
      for group in self.groups
    )
  
  def set_password_rotation(self):
    # Returns True if any group name contains "password_rotation"
    # Also attempts to parse password rotation timestamp if available
    in_group = any(
      "password_rotation" in group.get("name", "")
      for group in self.groups
    )

    timestamp = self.raw_facts_local.get("password_rotation", {}).get("run_timestamp", None)
    try:
      timestamp = int(timestamp)
      self.password_rotated_on = datetime.fromtimestamp(timestamp)
    except (TypeError, ValueError):
      self.password_rotated_on = None

    self.password_rotation = in_group

  
  def set_duo(self):
    self.duo = (self.lsa_host
            .get("mfa", {})
            .get("duo", False))

  def set_security_agents(self):
    expected_agents = ["threatdown", "crowdstrike", "nessus"]
    security_agents = self.lsa_host.get("security_agents", {})
    for agent in expected_agents:
      setattr(self, agent, security_agents.get(agent, {}).get("installed", None) == "true")
  
  def set_software(self):
    software_map = {
      "ad_bind": "lsa_ad_bind",
      "firewalld": "lsa_firewalld_dev_base"
    }
    for attr, fact_key in software_map.items():
      value = self.raw_facts_local.get(fact_key, {}).get("state") == "installed"
      setattr(self, attr, value)

  def to_dict(self):
    out = {}
    for name, default in self.FIELDS:
      out[name] = getattr(self, name, default)
    return out