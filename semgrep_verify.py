from semgrep import semgrep_test_in_tempdir, OK, SYNTAXERROR, COMMANDERROR
from dynamic import analysis_semgrep_output
import logging

def verify_one(rule, example, rn, tn):
    ok, msg = semgrep_test_in_tempdir(rule, example, rn, tn)
    if ok != OK:
        return False, SYNTAXERROR
    print(msg)

def verify_all(rule, example_set, rn, tn):
    result = []
    for e in example_set:
        result.append(verify_one(rule, e, rn, tn))
    return result