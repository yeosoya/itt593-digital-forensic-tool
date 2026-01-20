import pandas as pd

# Read Parquet file
df = pd.read_parquet("NF-UNSW-NB15.parquet")

# Save as CSV
df.to_csv("NF-UNSW-NB15.csv", index=False)

print("Conversion complete! CSV file created.")
