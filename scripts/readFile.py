import csv
import os
import subprocess
import re
from collections import defaultdict

# Settings
SOURCES = {
    "malicious": "codex-example-extensions",
    "safe": "safe-extension-samples"
}

DATABASES = {
    "malicious": "malicious-extensions-db",
    "safe": "safe-extensions-db"
}

QUERIES = [
    {"query_file": "codeql-queries/chrome.ql", "prefix": "chrome"},
    {"query_file": "codeql-queries/postMessage.ql", "prefix": "postMessage"},
    {"query_file": "codeql-queries/others.ql", "prefix": "others"},
    {"query_file": "codeql-queries/fetch.ql", "prefix": "fetch"},
]

TEMP_BQRS = "temp.bqrs"
COMBINED_OUTPUT = "combined_feed_chatgpt.csv"  # To be evaluated by ChatGPT


def run_codeql_query(query_file, database, output_csv):
    print(f"[*] Running CodeQL query: {query_file} on database: {database}")
    try:
        subprocess.run([
            "codeql", "query", "run",
            query_file,
            "--database", database,
            "--output", TEMP_BQRS
        ], check=True)

        subprocess.run([
            "codeql", "bqrs", "decode",
            TEMP_BQRS,
            "--format", "csv",
            "--output", output_csv
        ], check=True)

        print(f"[*] Query {query_file} completed and exported to {output_csv}")

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] CodeQL command failed for {query_file} with exit code {e.returncode}")
        exit(e.returncode)


def extract_nth_occurrence(file_path, line_num, function_name, occurrence_index):
    """Extracts the Nth occurrence of the method call on the given line using strict balancing."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        index = line_num - 1
        if index >= len(lines):
            return "[line number out of range]"

        # Get the entire remaining code from the line forward
        code = lines[index].strip()
        index += 1
        while index < len(lines):
            code += " " + lines[index].strip()
            index += 1

        # Find all occurrences
        matches = [m.start() for m in re.finditer(re.escape(function_name), code)]
        if len(matches) <= occurrence_index:
            return f"[only {len(matches)} occurrence(s) found, requested {occurrence_index}]"

        # Pick the Nth occurrence
        snippet_pos = matches[occurrence_index]

        after_snippet = code[snippet_pos:]
        paren_pos = after_snippet.find('(')
        if paren_pos == -1:
            return "[no opening parenthesis found after snippet]"

        extract_start = snippet_pos + paren_pos
        open_parens = 1
        i = extract_start + 1

        while i < len(code):
            if code[i] == '(':
                open_parens += 1
            elif code[i] == ')':
                open_parens -= 1
                if open_parens == 0:
                    return code[snippet_pos:i + 1].strip()
            i += 1

        return "[parentheses never balanced]"

    except Exception as e:
        return f"[error reading file: {e}]"


def add_code(input_csv, query_name, db_type):
    added_rows = []
    base_dir = SOURCES[db_type]
    
    with open(input_csv, newline='', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        headers = next(reader)
        
        # Counter for same function in same line of same file
        occurrence_counter = defaultdict(int)

        for row in reader:
            try:
                file_path = row[0]
                line_str = row[1]
                function_name = row[2]

                norm_file_path = os.path.normpath(file_path)
                abs_path = os.path.join(base_dir, norm_file_path)

                key = (abs_path, int(line_str), function_name)
                occurrence_index = occurrence_counter[key]

                print(f"[*] Extracting occurrence {occurrence_index+1} from: {abs_path} at line {line_str} for '{function_name}'")
                code = extract_nth_occurrence(
                    abs_path, int(line_str), function_name, occurrence_index
                )
                
                # Add db_type, query_name and extracted code to the row
                added_rows.append(row + [db_type, query_name, code])

                occurrence_counter[key] += 1

            except Exception as e:
                added_rows.append(row + [db_type, query_name, f"[error processing row: {e}]"])
    
    return headers, added_rows


if __name__ == "__main__":
    final_rows = []
    combined_headers = None
    
    for db_type, database in DATABASES.items():
        for query in QUERIES:
            query_file = query["query_file"]
            query_name = query["prefix"]
            output_csv = f"{db_type}_{query_name}_result.csv"

            # Run queries
            run_codeql_query(query_file, database, output_csv)
            
            # Extract the actual code
            headers, added_rows = add_code(output_csv, query_name, db_type)
            
            # Set combined headers
            if combined_headers is None:
                combined_headers = headers + ["db_type", "query_name", "extracted_code_block"]
            
            final_rows.extend(added_rows)
    
    # Write all results to a single file
    with open(COMBINED_OUTPUT, "w", newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(combined_headers)
        writer.writerows(final_rows)
    
    print(f"[*] All results combined in {COMBINED_OUTPUT}")