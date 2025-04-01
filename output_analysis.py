from semgrep import semgrep_test
from utils import *
import tempfile
import logging

def analysis_semgrep_output(output_json):
    """example return value:
    {"passed":passed,"fp":fp, "fn":fn, "example_path":file}
    """
    try:
        p = output_json['results']
    except:
        return {"passed":False,"fp":[], "fn":[], "example_path":""}
    for k in p:
        checks = p[k]['checks']
        if len(checks) == 0:
            return {"passed":True,"fp":[], "fn":[], "example_path":""}
        for kk in checks:
            passed = checks[kk]['passed']
            matches = checks[kk]['matches']
            for file in matches:
                expected_lines = set(matches[file]['expected_lines'])
                reported_lines = set(matches[file]['reported_lines'])
                fp_diff = reported_lines.difference(expected_lines)
                fn_diff = expected_lines.difference(reported_lines)
                fp = [l-1 for l in fp_diff]
                fn = [l-1 for l in fn_diff]
                ret = {"passed":passed,"fp":fp, "fn":fn, "example_path":file}
                logging.debug(f"semgrep_test: {ret}")
                return ret
    raise Exception("no checks in semgrep output")


if __name__ == "__main__":
    tc = "testcase/78b45a3f8cb654cb799ce871b5c16461e3f3f76a/before"
    ret = semgrep_test(tc)
    result = analysis_semgrep_output(ret)
    print(result)
    