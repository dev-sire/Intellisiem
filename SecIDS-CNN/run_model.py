import pandas as pd
from secids_cnn import SecIDSModel

# Step 1: Initialize the model
model = SecIDSModel()

# Step 2: Load network traffic data (replace 'path/to/your/data.csv' with the actual path)
data = pd.read_csv('path/to/your/data.csv')

predictions = model.predict(data)
print("Intrusion Detection Results:", predictions)