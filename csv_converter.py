import csv

def convert_dict_list_to_csv(dict_list, filename="output.csv"):
  if not dict_list:
    print("No data to write.")
    return
  
  # use Host.CSV_FIELDS for consistent column ordering; fallback to dict keys if needed
  fieldnames = dict_list[0].keys()
  
  with open(filename, 'w', newline='') as output_file:
    dict_writer = csv.DictWriter(output_file, fieldnames=fieldnames)
    dict_writer.writeheader()
    dict_writer.writerows(dict_list)
  print(f"Data written to {filename}")