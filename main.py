import awx
import csv_converter

if __name__ == "__main__":
	hosts = awx.get_hosts(page_size=200)
	host_dicts = [h.to_dict() for h in hosts]
	csv_converter.convert_dict_list_to_csv(host_dicts, filename="hosts.csv")
  
  # Uncomment below to fetch groups and save to CSV
	# groups = awx.get_groups(page_size=100)
	# csv_converter.convert_dict_list_to_csv(groups, filename="groups.csv")