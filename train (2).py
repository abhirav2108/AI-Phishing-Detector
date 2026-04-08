import pandas as pd

# Load the real dataset
df = pd.read_csv('dataset.csv')

# Print the column names
print(df.columns.tolist())