import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ==========================================
# Project: Cyber Threat Intelligence Analysis
# Name: JOBAYER AHMED REMON
# ID: 24-60206-3
# Dataset Source: Kaggle (OTX AlienVault)
# ==========================================

# ১. ডাটা লোড করা (Dataset Requirements)
df = pd.read_csv('1_otx_threat_intel.csv')

print("--- Data Understanding ---")
print(f"Dataset Shape: {df.shape}") # এটি দেখাবে ১০০০+ রো আছে[cite: 1]
print(df.info()) # কলামের ধরন দেখা[cite: 1]

# ২. ডাটা ক্লিনিং (Data Cleaning - অন্তত ৩টি ধাপ)[cite: 1]

# ধাপ ১: 'Description' কলামের খালি ঘর পূরণ করা[cite: 1]
df['Description'] = df['Description'].fillna('No Description')

# ধাপ ২: তারিখ ফরম্যাট ঠিক করা[cite: 1]
df['Created'] = pd.to_datetime(df['Created'], format='ISO8601')

# ধাপ ৩: NumPy ব্যবহার করে 'Indicators_Count' এর ভুল ডাটা হ্যান্ডেল করা[cite: 1]
# জিরো ভ্যালুগুলোকে গড় ভ্যালু দিয়ে রিপ্লেস করা (একটি জাস্টিফিকেশন)
mean_val = np.mean(df['Indicators_Count'])
df['Indicators_Count'] = df['Indicators_Count'].replace(0, mean_val)

# ৩. ফিচার ইঞ্জিনিয়ারিং (Feature Engineering - অন্তত ২টি নতুন কলাম)[cite: 1]

# কলাম ১: থ্রেট তৈরির মাস (Creation_Month)[cite: 1]
df['Creation_Month'] = df['Created'].dt.month_name()

# কলাম ২: ট্যাগের সংখ্যা (Tag_Complexity)[cite: 1]
df['Tag_Count'] = df['Tags'].apply(lambda x: len(str(x).split(',')))

# ৪. ভিজ্যুয়ালাইজেশন (Visualization - ৪টি চার্ট)[cite: 1]

# চার্ট ১: মাসে মাসে থ্রেটের সংখ্যা (Bar Chart)[cite: 1]
plt.figure(figsize=(10,6))
df['Creation_Month'].value_counts().plot(kind='bar', color='orange')
plt.title('Threat Distribution by Month')
plt.xlabel('Month')
plt.ylabel('Count')
plt.tight_layout()
plt.show()

# চার্ট ২: টপ ১০টি ম্যালওয়্যার ফ্যামিলি (Horizontal Bar Chart)[cite: 1]
plt.figure(figsize=(12, 6))
df['Malware_Families'].value_counts().head(10).plot(kind='barh', color='teal')
plt.title('Top 10 Malware Families Identified')
plt.xlabel('Number of Cases')
plt.ylabel('Malware Family')
plt.tight_layout()
plt.show()

# চার্ট ৩: TLP লেভেলের ডিস্ট্রিবিউশন (Pie Chart)[cite: 1]
plt.figure(figsize=(8, 8))
df['TLP'].value_counts().plot(kind='pie', autopct='%1.1f%%')
plt.title('Distribution of Traffic Light Protocol (TLP) Levels')
plt.ylabel('')
plt.show()

# চার্ট ৪: ইনডিকেটর কাউন্ট বনাম সাবস্ক্রাইবার (Scatter Plot - Relationship Analysis)[cite: 1]
plt.figure(figsize=(10, 6))
plt.scatter(df['Indicators_Count'], df['Subscribers'], alpha=0.5, color='purple')
plt.title('Relationship: Indicators Count vs. Subscribers')
plt.xlabel('Indicators Count')
plt.ylabel('Subscribers')
plt.grid(True)
plt.show()

print("\n--- Project Analysis Complete ---")