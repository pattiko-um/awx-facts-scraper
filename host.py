import json
import awx

class Host:
  SOFTWARE_MAP = {
    "ad_bind": "lsa_ad_bind",
    "firewalld": "lsa_firewalld_dev_base",
    "threatdown": "mwalwarebytes",
    "crowdstrike": "lsa_falcon_sensor",
    "tenable": "NessusAgent_10_8_2"
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
    # always set identifying attributes
    self.awx_id = raw_data['id']
    self.hostname = raw_data.get('name')

    # set container attributes
    self.variables = {}
    self.raw_facts = {}
    self.raw_facts_local = {}
    self.facts = {}

    # initialize canonical defaults for known fields and software
    self.init_defaults()

    has_variables = raw_data.get('variables')
    if has_variables:
      self.build_host(raw_data)

  def init_defaults(self):
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

  def build_empty_host(self):
    # kept for compatibility; simply (re)initialize defaults
    self.init_defaults()

  def build_host(self, raw_data):
    # load variables safely
    self.variables = json.loads(raw_data.get('variables') or '{}')
    self.raw_facts = awx.get_host_facts(self.awx_id)
    self.raw_facts_local = self.raw_facts.get("ansible_local", {})

    self.support_group = self.variables.get("foreman_location_name", "Unassigned")
    self.hostname = self.raw_facts_local.get("lsa_host", {}).get("hostname", self.hostname or "Unknown")
    self.os = self.raw_facts_local.get("lsa_host", {}).get("os", {}).get("tdx_friendly", "Unknown")
    self.host_collection = "Placeholder"
    self.password_rotation = "Placeholder"
    self.ubuntu_pro = self.raw_facts_local.get("ubuntu_pro", {}).get("attached", None)
    self.duo = "Placeholder"
    self.ldap = "Placeholder"

    self.set_installed_software()

  def set_installed_software(self):
    for attr, fact_key in self.SOFTWARE_MAP.items():
      setattr(self, attr, self.raw_facts_local.get(fact_key, {}).get("state") == "installed")

  def to_dict(self):
    out = {}
    for key in self.CSV_FIELDS:
      out[key] = getattr(self, key, None)
    return out