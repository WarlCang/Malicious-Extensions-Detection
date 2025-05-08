import csv
import os

INPUT_CSV = "result.csv"
OUTPUT_CSV = "result_with_code.csv"
BASE_DIR = "codex-example-extensions"

with open(INPUT_CSV, newline='', encoding='utf-8') as infile, \
     open(OUTPUT_CSV, "w", newline='', encoding='utf-8') as outfile:

    reader = csv.reader(infile)
    writer = csv.writer(outfile)

    headers = next(reader)
    writer.writerow(headers + ["code_line"])

    for row in reader:
        file_path, line_str, *rest = row

        # Normalize slashes for Windows
        norm_file_path = os.path.normpath(file_path)

        # Join with base directory
        abs_path = os.path.join(BASE_DIR, norm_file_path)

        print(f"Trying: {abs_path}")

        try:
            with open(abs_path, encoding='utf-8') as f:
                lines = f.readlines()
                line_num = int(line_str)
                code_line = lines[line_num - 1].strip() if line_num <= len(lines) else "[line not found]"
        except Exception as e:
            code_line = f"[error reading file: {e}]"

        writer.writerow(row + [code_line])
