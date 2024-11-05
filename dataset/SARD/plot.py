import pandas as pd
import matplotlib.pyplot as plt

# Leggi il CSV unito
merged_df = pd.read_csv('merged_output.csv')

print(merged_df.shape)

# length of "Source" and "Region" columns
merged_df['Source_length'] = merged_df['Source'].apply(len)
merged_df['Region_length'] = merged_df['Region'].astype(str).apply(len)

# info about df
info = merged_df.info()

# count classes on column "CWE"
cwe_counts = merged_df['CWE'].value_counts()
print(f"Conteggio delle classi 'CWE':\n{cwe_counts}\n")

# Divide classes by frequences
cwe_groups = pd.qcut(cwe_counts.rank(method='first'), 4, labels=["Rare", "Poco frequenti", "Mediamente frequenti", "Molto frequenti"])

# Create DF with counts and groups
cwe_counts_df = pd.DataFrame({'CWE': cwe_counts.index, 'Frequenza': cwe_counts.values, 'Gruppo': cwe_groups.values})

# Plot frequency CWE class for each group
fig, axes = plt.subplots(4, 1, figsize=(15, 48))

for (group, data), ax in zip(cwe_counts_df.groupby('Gruppo'), axes):
    data.set_index('CWE')['Frequenza'].plot(kind='bar', ax=ax)
    ax.set_ylabel('Frequenza')
    ax.tick_params(axis='x', rotation=45)

plt.tight_layout()
plt.show()
