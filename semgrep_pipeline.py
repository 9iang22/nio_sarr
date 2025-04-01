from semgrep_locate import lcp_locate
from semgrep2nx import Semgrep2NX
from example import Example
from typing import List
from semgrep import semgrep_explanation_in_tempdir
import json
import logging
import copy
import sys
from semgrep_template import gen_template
from semgrep_prompt import gen_prompt, postprocess
import tqdm
from para import map_reduce
import os


from doubao import chat
# from deepseek import chat

def prepare_data(d)->List[Example]:
    example_set = []
    for test, expect, actual in zip(d['splited_testsuite_b'], d['expected'], d['actual']):
        example_set.append(Example(d['test_path'], d['rule_path'], test, "semgrep", expect, actual))
    return example_set

# def syntax_check(new_rule, e):
#     try:
#         output, error = semgrep_explanation_in_tempdir(new_rule, e.content, e.rname, e.tname)
#         d = json.loads(output)
#         return True
#     except:
#         return False

# def regression(new_rule, old_rule, example_set):
#     try:
#         correct_set = [e for e in example_set if e.ok()]
#         for e in correct_set:
#             output, error = semgrep_explanation_in_tempdir(old_rule, e.content, e.rname, e.tname)
#             d1 = json.loads(output)
#             output, error = semgrep_explanation_in_tempdir(new_rule, e.content, e.rname, e.tname)
#             d2 = json.loads(output)
#             if d1['explanations'][0]['matches'] == d2['explanations'][0]['matches']:
#                 continue
#         return True 
#     except Exception as e:
#         logging.error(f"regression check failed: {e}")
#         return False

# def verify_fix(new_rule, incorrect):
#     output, error = semgrep_explanation_in_tempdir(new_rule, incorrect.content, incorrect.rname, incorrect.tname)
#     d1 = json.loads(output)
#     matches = d1['explanations'][0]['matches']
#     # return (matches != []) ^ incorrect.actual
#     if incorrect.is_fp() and matches == []:
#         return True
#     elif incorrect.is_fn() and matches != []:
#         return True
#     else:
#         return False

from semgrep import semgrep_test_in_tempdir, OK, SYNTAXERROR, COMMANDERROR

def syntax_check(new_rule, e):
    try:
        ok, msg = semgrep_test_in_tempdir(new_rule, e.content, e.rname, e.tname)
        return ok == OK
    except:
        return False

def regression(new_rule, old_rule, example_set):
    correct_set = [e for e in example_set if e.ok()]
    for e in correct_set:
        try:
            ok, msg = semgrep_test_in_tempdir(new_rule, e.content, e.rname, e.tname)
            assert ok == OK
            from output_analysis import analysis_semgrep_output
            ret = analysis_semgrep_output(msg)
            if ret == None or ret['passed'] == False:
                return False
        except Exception as e:
            logging.error(f"regression check failed: {e}")
            return False
    return True

def verify_fix(new_rule, incorrect):
    try:
        ok, msg = semgrep_test_in_tempdir(new_rule, incorrect.content, incorrect.rname, incorrect.tname)
        assert ok == OK
        from output_analysis import analysis_semgrep_output
        ret = analysis_semgrep_output(msg)
        return ret['passed']
    except Exception as e:
        logging.error(f"verify fix failed: {e}")
        return False

def pipeline(old_rule, example_set):
    OK = 0b0000
    REFINE_FAILED = 0b0001
    SYNTAX_ERROR = 0b0010
    REGRESSION_FAILED = 0b0100

    correct_set = [e for e in example_set if e.ok()]
    positive_set = [e for e in correct_set if e.actual]
    negative_set = [e for e in correct_set if not e.actual]

    incorrect = [e for e in example_set if not e.ok()][0]

    
    logging.debug(f"find incorrect case: \n{incorrect.content}")
    if incorrect.is_fn():
        localization = lcp_locate(old_rule, positive_set, incorrect)
    else:
        localization = lcp_locate(old_rule, negative_set, incorrect)

    if len(localization) >= 5:
        localization = localization[:5]
    logging.debug(f"localize at {localization}")

    results = []
    for loc in localization:
        template = gen_template(incorrect, loc)
        if incorrect.is_fp():
            prompt = gen_prompt(template, incorrect.content, "false positive")
        elif incorrect.is_fn():
            prompt = gen_prompt(template, incorrect.content, "false negative")
        else:
            raise ValueError("incorrect case is not fp or fn")
        r = chat(prompt)
        expl, result = postprocess(r)
        # logging.info(f"result: {result}")

        new_rule = result
        res = OK
        if not syntax_check(new_rule, incorrect):
            res |= SYNTAX_ERROR | REFINE_FAILED | REGRESSION_FAILED
        else:
            if not regression(new_rule, old_rule, example_set):
                res |= REGRESSION_FAILED
            if not verify_fix(new_rule, incorrect):
                res |= REFINE_FAILED
        results.append({"rule":new_rule, "result": res})
    return results

def prepare_prompts(old_rule, example_set, mode):
    correct_set = [e for e in example_set if e.ok()]
    positive_set = [e for e in correct_set if e.actual]
    negative_set = [e for e in correct_set if not e.actual]

    incorrects = [e for e in example_set if not e.ok()]

    results = []

    if mode == "simple":
        for incorrect in incorrects:
            prompt = gen_prompt(old_rule, incorrect.content, "false positive" if incorrect.is_fp() else "false negative", mode)
            results.append({"prompt":prompt, "template":old_rule, "incorrect":incorrect.content, "type": "fp" if incorrect.is_fp() else "fn"})
        return results
    
    # full mode
    logging.debug(f"find {len(incorrects)} incorrect cases")
    for incorrect in incorrects:
        logging.debug(f"find incorrect case: \n{incorrect.content}")
        if incorrect.is_fn() and len(positive_set) == 0 or incorrect.is_fp() and len(negative_set) == 0:
            prompt = gen_prompt(old_rule, incorrect.content, "false positive" if incorrect.is_fp() else "false negative", mode)
            results.append({"prompt":prompt, "template":old_rule, "incorrect":incorrect.content, "type": "fp" if incorrect.is_fp() else "fn"})
            continue
        if incorrect.is_fn():
            localization = lcp_locate(old_rule, positive_set, incorrect)
        else:
            localization = lcp_locate(old_rule, negative_set, incorrect)
        if localization == []:
            logging.warning(f"no localization found")
            continue
        if len(localization) >= 5:
            localization = localization[:5]
        logging.debug(f"localize at {localization}")

        for loc in localization:
            try:
                template = gen_template(incorrect, loc)
                if incorrect.is_fp():
                    prompt = gen_prompt(template, incorrect.content, "false positive")
                elif incorrect.is_fn():
                    prompt = gen_prompt(template, incorrect.content, "false negative")
                else:
                    raise ValueError("incorrect case is not fp or fn")
            except:
                logging.error(f"rule: {old_rule}, incorrect: {incorrect.content}")   
                continue
            results.append({"prompt":prompt, "template":template, "incorrect":incorrect.content, "type": "fp" if incorrect.is_fp() else "fn"})
    return results

def query_all(data):
    from doubao import chat_raw
    from para import map_reduce
    def mapf(d):
        prompt = d['prompt']['prompt']
        r = chat_raw(prompt)
        d['response'] = r
        return d
    reducef = lambda x: x
    return map_reduce(data, mapf, reducef, max_workers=len(data))

def check_one(d):
    example_set = prepare_data(d)
    correct_set = [e for e in example_set if e.ok()]
    positive_set = [e for e in correct_set if e.actual]
    negative_set = [e for e in correct_set if not e.actual]

    incorrect = d['prompt']['incorrect']
    find = None
    for e in example_set:
        if e.content == incorrect:
            find = e
            break
    assert find
    incorrect = find

    old_rule = d['rule']
    response = json.loads(d['response'])
    expl, new_rule = postprocess(response['choices'][0]['message']['content'])

    verify_results = []
    if not syntax_check(new_rule, incorrect):
        verify_results.append("SYNTAX_ERROR")
    else:
        if not regression(new_rule, old_rule, example_set):
            verify_results.append("REGRESSION_FAILED")
        if not verify_fix(new_rule, incorrect):
            verify_results.append("REFINE_FAILED")
        else:
            verify_results.append("REFINE_SUCCESS")
    d['verify_result'] = verify_results
    return d

def check_all(data):
    return map_reduce(data, check_one, lambda x: x, max_workers=len(data))

def gen_all_prompts(data, mode):    
    results = []

    def mapf(d):
        example_set = prepare_data(d)
        results = prepare_prompts(d['rule'], example_set, mode)
        res = []
        for r in results:
            d = copy.deepcopy(d)
            d['prompt'] = r
            res.append(d)
        return res
    
    def reducef(x):
        res = []
        for xx in x:
            res.extend(xx)
        return res
    
    results = map_reduce(data, mapf, reducef, max_workers=len(data))
    # for d in tqdm.tqdm(data):
    #     rule = d['rule']
    #     example_set = prepare_data(d)
    #     results = prepare_prompts(rule, example_set)
    #     for r in results:
    #         d = copy.deepcopy(d)
    #         d['prompt'] = r
    #         results.append(d)
    return results

def test():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
    data = json.load(open("examples/localization.json"))
    rule = data['rule']
    rname = data['rule_path']
    tname = data['test_path']
    tests = data['splited_testsuite_b']
    example_set = [Example(tname, rname, tests[0], "semgrep", True, True),
                   Example(tname, rname, tests[1], "semgrep", False, False),
                   Example(tname, rname, tests[2], "semgrep", False, False),
                   Example(tname, rname, tests[3], "semgrep", False, True)]
    results = pipeline(rule, example_set)
    print(results)

"""
{"custom_id": "request-1", "body": {"messages": [{"role": "user", "content": "天空为什么这么蓝？"}],"max_tokens": 1000,"top_p":1}}
{"custom_id": "request-2", "body": {"messages": [{"role": "system", "content": "You are an unhelpful assistant."},{"role": "user", "content": "天空为什么这么蓝？"}],"max_tokens": 1000}}
"""
def batch(infile, outfile):
    from doubao import doubao_jsonl
    import sys
    with open(infile) as f:
        lines = f.readlines()
    data = [json.loads(line) for line in lines]
    with open(outfile+".batch", "a") as o:
        with open(outfile+".map", "a") as m:
            for i, d in enumerate(data):
                r = doubao_jsonl(d['prompt']['prompt'], f"request-{i}")
                o.write(json.dumps(r) + "\n")
                d['custom_id'] = f"request-{i}"
                m.write(json.dumps(d) + "\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", type=str, default="full")
    parser.add_argument("-i", "--input", type=str)
    parser.add_argument("-o", "--output_dir", type=str)
    args = parser.parse_args()

    if args.mode not in ["simple", "full"]:
        raise ValueError("mode must be `simple` or `full`")
    
    if args.input is None:
        raise ValueError("input file is required, see dataset/example.jsonl")

    if os.path.exists(args.output_dir):
        raise ValueError(f"{args.output_dir} already exists")
    os.makedirs(args.output_dir)

    data = [json.loads(line) for line in open(args.input).readlines()]

    data = gen_all_prompts(data, "full")
    prompt_file = os.path.join(args.output_dir, "prompts.jsonl")
    with open(prompt_file, "w+") as o:
        for d in data:
            o.write(json.dumps(d) + "\n")

    data = [json.loads(line) for line in open(prompt_file).readlines()]
    results = query_all(data)
    result_file = os.path.join(args.output_dir, "results.jsonl")
    with open(result_file, "w+") as o:
        for r in results:
            o.write(json.dumps(r) + "\n")


    data = [json.loads(line) for line in open(result_file).readlines()]
    results = check_all(data)
    verify_file = os.path.join(args.output_dir, "verify.jsonl")
    with open(verify_file, "w+") as o:
        for r in results:
            o.write(json.dumps(r) + "\n")

        

