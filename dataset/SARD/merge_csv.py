import os
import pandas as pd
import matplotlib.pyplot as plt

# set path
folder_path = 'csv_file'

# list for save DFs
dataframes = []

# read CSV in path
for file_name in os.listdir(folder_path):
    if file_name.endswith('.csv'):
        file_path = os.path.join(folder_path, file_name)
        df = pd.read_csv(file_path)
        dataframes.append(df)

# Merge all DFs into single DF
merged_df = pd.concat(dataframes, ignore_index=True)

# Save new DF into CSV file
output_file_path = 'merged_output.csv'
merged_df.to_csv(output_file_path, index=False)

# info about CWE column
cwe_classes = merged_df['CWE'].unique()
print(f"Classi presenti sotto la colonna 'CWE':\n{cwe_classes}\n")