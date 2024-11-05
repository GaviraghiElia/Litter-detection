import os
import json
import re
import pandas as pd
from tqdm import tqdm  # Importa tqdm per la barra di progressione

# Test suite path
base_dir = r'set-path'

def remove_comments_c(code):
    pattern = r'(/\*([^*]|(\*+([^*/])))*\*+/|//.*)'
    return re.sub(pattern, '', code, flags=re.MULTILINE)

def extract_code_from_region(source_code, region):
    start_line = region['startLine']
    end_line = region.get('endLine', start_line)  # Se non c'è endLine, usa startLine
    specific_lines = source_code.splitlines()[start_line - 1:end_line]
    specific_code = '\n'.join(specific_lines)
    return specific_code

all_sources = []
all_cwe_classes = []
all_ids = []
all_regions = []
problematic_folders = []

for suite_folder in tqdm(os.listdir(base_dir), desc='Processing suites'):
    suite_path = os.path.join(base_dir, suite_folder)

    if os.path.isdir(suite_path):
        manifest_file = os.path.join(suite_path, 'manifest.sarif')

        if os.path.isfile(manifest_file):
            with open(manifest_file, 'r') as f:
                sarif_data = json.load(f)

            language = sarif_data['runs'][0]['properties']['language'].lower()

            if language not in ['c', 'c++', 'cplusplus']:
                print(f"Language not supported find: {language} into file {manifest_file}")
                continue

            for run in sarif_data['runs']:
                for result in run['results']:
                    cwe_class = result['ruleId']
                    cwe_classes = cwe_class  # Rimuove le parentesi quadre

                    if 'locations' in result and result['locations']:
                        location = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
                        source_file = os.path.join(suite_path, location)
                        try:
                            with open(source_file, 'r') as src_file:
                                source_code = src_file.read()  # Leggi tutto il contenuto come stringa

                                if language == 'c':
                                    source_code = remove_comments_c(source_code)

                                if 'region' in result['locations'][0]['physicalLocation']:
                                    region = result['locations'][0]['physicalLocation']['region']
                                    specific_code = extract_code_from_region(source_code, region)
                                    all_sources.append(source_code)
                                    all_regions.append(specific_code)  # Aggiunge direttamente il codice specifico
                                else:
                                    all_sources.append(source_code)
                                    all_regions.append(None)
                                    problematic_folders.append(suite_path)  # Aggiungi la cartella problematica

                                all_cwe_classes.append(cwe_classes)
                                all_ids.append(run['properties']['id'])

                        except Exception as e:
                            print(f"Error reading file {source_file}: {e}")

df = pd.DataFrame({
    'CWE': all_cwe_classes,
    'ID': all_ids,
    'Source': all_sources,
    'Region': all_regions
})

df.to_csv('juliet.csv', index=False)
print(df.head())
print(df.shape)
print(df.iloc[1])

# Stampa le cartelle problematiche
print("\nCartelle con problemi nella colonna 'Region':")
for folder in problematic_folders:
    print(folder)