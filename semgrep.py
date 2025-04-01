import subprocess
import json
import os
import logging
from typing import Tuple

SEMGREP_PATH = f"semgrep"

OK = 0
SYNTAXERROR = 1 << 0
COMMANDERROR = 1 << 1

def find_semgrep_rules(path):
    result = []
    files = os.listdir(path)
    for file in files:
        if file.endswith(".yaml"):
            result.append(file)
    logging.debug(f"find_semgrep_rules: {result}")
    return result

def find_semgrep_test(path, rule):
    files = os.listdir(path)
    rule_name = rule[:rule.rindex(".")]
    for file in files:
        if file.startswith(rule_name+"."):
            logging.debug(f"find_semgrep_test: {file}")
            return file
    logging.debug(f"find_semgrep_test: failed")
    return None

def split_semgrep_test(lineno, tests):
    logging.debug(f"unexcepted lineno {lineno}, full tests:\n{tests}")
    lines = tests.split('\n')
    failed_test = lines[lineno] + '\n'
    for idx, line in enumerate(lines):
        if idx <= lineno:
            continue
        if "ruleid:" in line or \
            "ok:" in line or \
            "OK:" in line or \
            "todoruleid:" in line or \
            "todook:" in line :
            break
        failed_test += line + "\n"
    return failed_test

def semgrep_test_in_tempdir(rule, test, rule_path, test_path) -> Tuple[int, dict]:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="sarr_") as tempdir:
        with open(os.path.join(tempdir, os.path.basename(rule_path)), "w") as f:
            f.write(rule)
        with open(os.path.join(tempdir, os.path.basename(test_path)), "w") as f:
            f.write(test)
        return semgrep_test(tempdir)

def semgrep_test(path) -> Tuple[int, dict]:
    cmd = f"{SEMGREP_PATH} test -q --json {path} || true"
    logging.debug(f"run_semgrep_test: {cmd}")
    return run_semgrep(cmd)

def semgrep_scan_in_tempdir(rule, test, rule_path, test_path) -> Tuple[int, dict]:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="sarr_") as tempdir:
        with open(os.path.join(tempdir, os.path.basename(rule_path)), "w") as f:
            f.write(rule)
        with open(os.path.join(tempdir, os.path.basename(test_path)), "w") as f:
            f.write(test)
        return semgrep_scan(tempdir)

def semgrep_scan(path):
    files = os.listdir(path)
    test_path = None
    rule_path = None
    for file in files:
        if file.endswith(".yaml"):
            rule_path = os.path.join(path, file)
        else:
            test_path = os.path.join(path, file)
    if not test_path or not rule_path:
        return COMMANDERROR, "cannot find test or rule file"
    
    cmd = f"{SEMGREP_PATH} scan --json --config {rule_path} {test_path} || true"
    logging.debug(f"run semgrep scan: {cmd}")
    result = subprocess.run(cmd, shell=True, check=True, 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Decode the output from bytes to string
    output = result.stdout.decode('utf-8')
    error = result.stderr.decode('utf-8')
    return output, error

def semgrep_explanation(path):
    files = os.listdir(path)
    test_path = None
    rule_path = None
    for file in files:
        if file.endswith(".yaml"):
            rule_path = os.path.join(path, file)
        else:
            test_path = os.path.join(path, file)
    if not test_path or not rule_path:
        return "", "cannot find test or rule file"
    
    cmd = f"{SEMGREP_PATH} scan --matching-explanations --json --config {rule_path} {test_path} || true"
    logging.debug(f"run semgrep explain: {cmd}")
    result = subprocess.run(cmd, shell=True, check=True, 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Decode the output from bytes to string
    output = result.stdout.decode('utf-8')
    error = result.stderr.decode('utf-8')
    return output, error

def semgrep_explanation_in_tempdir(rule, test, rule_path, test_path):
    import tempfile
    with tempfile.TemporaryDirectory(prefix="sarr_") as tempdir:
        with open(os.path.join(tempdir, os.path.basename(rule_path)), "w") as f:
            f.write(rule)
        with open(os.path.join(tempdir, os.path.basename(test_path)), "w") as f:
            f.write(test)
        return semgrep_explanation(tempdir)

def semgrep_validate_in_tempdir(rule, rule_path) -> Tuple[int, dict]:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="sarr_") as tempdir:
        with open(os.path.join(tempdir, os.path.basename(rule_path)), "w") as f:
            f.write(rule)
        return semgrep_validate(os.path.join(tempdir, os.path.basename(rule_path)))

def semgrep_validate(path) -> Tuple[int, dict]:
    cmd = f"{SEMGREP_PATH} --validate --config {path} || true"
    logging.debug(f"run_semgrep_validate: {cmd}")
    result = subprocess.run(cmd, shell=True, check=True, 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Decode the output from bytes to string
    output = result.stdout.decode('utf-8')
    error = result.stderr.decode('utf-8')
    return output, error

def run_semgrep(command):
    """
    Execute a Semgrep command and return the output.

    Parameters:
    command (str): The Semgrep command to execute.

    Returns:
    str: The output from the Semgrep command.
    """
    try:
        # Run the Semgrep command
        result = subprocess.run(command, shell=True, check=True, 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Decode the output from bytes to string
        output = result.stdout.decode('utf-8')
        error = result.stderr.decode('utf-8')
        try:
            return OK, json.loads(output)
        except json.decoder.JSONDecodeError as e:
            logging.debug(f"semgrep broken json {error}")
            return SYNTAXERROR, f"broken json : {error}"
    except subprocess.CalledProcessError as e:
        # Handle errors in execution
        error_message = e.stderr.decode('utf-8')
        print(f"Error executing command: {error_message}")
        return COMMANDERROR, error_message
