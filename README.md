# Malicious-Extensions-Detection
A project for course DD2525 Language-based Security at KTH. Using CodeQL and Python to extract potentially problematic code, and store them in a csv file which is later sent to (Manually) and evaluated by ChatGPT.

## Dependencies
To run this project, CodeQL and Python is required. How to install CodeQL: [Setting up the CodeQL CLI - GitHub Docs](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli)


## Test
To test our program and queries, simply run the python file readFile.py at root directory.

To test our queries individually use following commands:
```bash
codeql query run --database=DATABASE_NAME codeql-queries/QUERY_FILE --output=result.bqrs
```
then
```bash
codeql bqrs decode --format=csv --output=result.csv result.bqrs
```
