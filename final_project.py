import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ==========================================
# Project: Cyber Threat Intelligence Analysis
# Name: JOBAYER AHMED REMON
# ID: 24-60206-3
# Dataset Source: Kaggle (OTX AlienVault)
# ==========================================


df = pd.read_csv('1_otx_threat_intel.csv')

print("--- Data Understanding ---")
print(f"Dataset Shape: {df.shape}")
print(df.info()) 



df['Description'] = df['Description'].fillna('No Description')


df['Created'] = pd.to_datetime(df['Created'], format='ISO8601')


mean_val = np.mean(df['Indicators_Count'])
print(f"Mean of Indicators Count: {mean_val}")
df['Indicators_Count'] = df['Indicators_Count'].replace(0, mean_val)




df['Creation_Month'] = df['Created'].dt.month_name()


df['Tag_Count'] = df['Tags'].apply(lambda x: len(str(x).split(',')))


plt.figure(figsize=(10,6))
df['Creation_Month'].value_counts().plot(kind='bar', color='orange')
plt.title('Threat Distribution by Month')
plt.xlabel('Month')
plt.ylabel('Count')
plt.tight_layout()
plt.show()


plt.figure(figsize=(12, 6))
df['Malware_Families'].value_counts().head(10).plot(kind='barh', color='teal')
plt.title('Top 10 Malware Families Identified')
plt.xlabel('Number of Cases')
plt.ylabel('Malware Family')
plt.tight_layout()
plt.show()


plt.figure(figsize=(8, 8))
df['TLP'].value_counts().plot(kind='pie', autopct='%1.1f%%')
plt.title('Distribution of Traffic Light Protocol (TLP) Levels')
plt.ylabel('')
plt.show()


plt.figure(figsize=(10, 6))
plt.scatter(df['Indicators_Count'], df['Subscribers'], alpha=0.5, color='purple')
plt.title('Relationship: Indicators Count vs. Subscribers')
plt.xlabel('Indicators Count')
plt.ylabel('Subscribers')
plt.grid(True)
plt.show()

print("\n--- Project Analysis Complete ---")