import awx
import csv_converter

if __name__ == "__main__":
	hosts = awx.get_hosts(page_size=10)
	dict_list = [h.to_dict() for h in hosts]
	csv_converter.convert_dict_list_to_csv(dict_list, filename="hosts.csv")
  
	# groups = awx.get_groups(page_size=100)
	# csv_converter.convert_dict_list_to_csv(groups, filename="groups.csv")