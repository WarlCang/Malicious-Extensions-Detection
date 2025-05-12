import csv
import os
import subprocess

INPUT_CSV = "result.csv"
OUTPUT_CSV = "result_with_code.csv"
BASE_DIR = "codex-example-extensions"
CODEQL_DB = "malicious-extensions-db"
QUERY_FILE = "codeql-queries/bookmark.ql"
TEMP_BQRS = "temp.bqrs"

def run_codeql_query():
    print("[*] Running CodeQL query...")
    try:
        # 1. Run the query safely
        subprocess.run([
            "codeql", "query", "run",
            QUERY_FILE,
            "--database", CODEQL_DB,
            "--output", TEMP_BQRS
        ], check=True)

        # 2. Decode the bqrs to CSV
        subprocess.run([
            "codeql", "bqrs", "decode",
            TEMP_BQRS,
            "--format", "csv",
            "--output", INPUT_CSV
        ], check=True)

        print("[*] Query and export completed successfully.")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] CodeQL command failed with exit code {e.returncode}")
        exit(e.returncode)

def enrich_csv():
    with open(INPUT_CSV, newline='', encoding='utf-8') as infile, \
         open(OUTPUT_CSV, "w", newline='', encoding='utf-8') as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        headers = next(reader)
        writer.writerow(headers + ["code_line"])

        for row in reader:
            file_path, line_str, *rest = row

            norm_file_path = os.path.normpath(file_path)
            abs_path = os.path.join(BASE_DIR, norm_file_path)

            print(f"Trying: {abs_path}")

            try:
                with open(abs_path, encoding='utf-8') as f:
                    lines = f.readlines()
                    line_num = int(line_str)

                    code_line = ""
                    index = line_num - 1
                    bracket_count = 0
                    started = False

                    while index < len(lines):
                        current_line = lines[index].strip()
                        code_line += current_line + " "

                        for char in current_line:
                            if char == "{":
                                bracket_count += 1
                                started = True
                            elif char == "}":
                                bracket_count -= 1

                        if started and bracket_count == 0:
                            break

                        index += 1

                    if not started:
                        code_line = lines[line_num - 1].strip() if line_num <= len(lines) else "[line not found]"

            except Exception as e:
                code_line = f"[error reading file: {e}]"

            writer.writerow(row + [code_line])

if __name__ == "__main__":
    run_codeql_query()
    enrich_csv()
