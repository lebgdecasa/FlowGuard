import os
import pandas as pd

def merge_csv_files(input_dir, output_file):
    """
    Merges all CSV files in a directory into a single CSV file.

    Args:
        input_dir (str): The path to the directory containing the CSV files.
        output_file (str): The path to the output CSV file.
    """
    csv_files = [f for f in os.listdir(input_dir) if f.endswith(".csv")]
    if not csv_files:
        print("No CSV files found in the directory.")
        return

    df_list = []
    for csv_file in csv_files:
        file_path = os.path.join(input_dir, csv_file)
        df = pd.read_csv(file_path)
        df_list.append(df)

    merged_df = pd.concat(df_list, ignore_index=True)
    merged_df.to_csv(output_file, index=False)
    print(f"Successfully merged {len(csv_files)} CSV files into {output_file}")

if __name__ == "__main__":
    input_directory = "raw_data"
    output_csv_file = "merged_data.csv"
    merge_csv_files(input_directory, output_csv_file)
