import json, pandas as pd, collections, os

# Load the JSON data
json_path = "ta_vulnerable_destinations.json"
with open(json_path, "r") as f:
    data = json.load(f)

rows = []
for item in data:
    vd = item["vd"]
    param_index = vd.get("param_index")
    line = vd.get("line")
    sink = vd.get("sink")

    for chain in item["chains"]:
        padded_chain = chain + [""] * (5 - len(chain))
        row = padded_chain[:5] + [param_index, line, sink]
        rows.append(row)

df = pd.DataFrame(
    rows,
    columns=["fase1", "fase2", "fase3", "fase4", "fase5",
             "param_index", "line", "sink"]
)

# Save to Excel
excel_path = "ta_chains_with_sink.xlsx"
df.to_excel(excel_path, index=False)

# Show a preview (first 10 rows) to the user
print("Preview (first 10 rows):")
print(df.head(10))

print(f"Excel file saved to: {excel_path}")
