import pandas as pd

# Load the CSV
#data = pd.read_csv("modsec_audit_diff_ip.csv")
data = pd.read_csv("modsec_audit_222.csv")

#Strip column name
data.columns = data.columns.str.strip()

# Define DDoS prediction based on status code
data['Predicted_DDoS'] = data['response_status'].isin([403, 400]).astype(int)

# Calculate TP, FP, TN, FN
TP = len(data[(data['Predicted_DDoS'] == 1) & (data['Label'] == 1)])
FP = len(data[(data['Predicted_DDoS'] == 1) & (data['Label'] == 0)])
TN = len(data[(data['Predicted_DDoS'] == 0) & (data['Label'] == 0)])
FN = len(data[(data['Predicted_DDoS'] == 0) & (data['Label'] == 1)])

print(f"True Positives (TP): {TP}")
print(f"False Positives (FP): {FP}")
print(f"True Negatives (TN): {TN}")
print(f"False Negatives (FN): {FN}")

accuracy = ((TP+TN)/(TP+TN+FP+FN))
precision = (TP/(TP+FP))
recall = (TP/(TP+FN))
F1_score = (2*((precision*recall)/(precision+recall)))

print(f"Accuracy:  {round(accuracy,2)}")
print(f"Precision:  {precision}")
print(f"Recall:  {round(recall,2)}")
print(f"F1-Score:  {round(F1_score,2)}")

#TP indicates True DDoS
#FP indicates Legitimate indicated as DDoS
#TN indicates Legitimate indicates as DDoS correctly
#FN indicates DDoS indicated Normal incorrectly