from semgrep_locate import lcp_locate
from semgrep2nx import Semgrep2NX
from example import Example
from typing import List
#from deepseek import chat
from doubao import chat
from semgrep import semgrep_explanation_in_tempdir
import json
import logging
import copy
import sys
from semgrep_template import gen_template
from semgrep_prompt import gen_prompt, postprocess
import tqdm
from para import map_reduce
import semgrep_pipeline
import graph

def motivation_example():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
    data = json.load(open("examples/motivation_example.json"))
    rule = data['rule']
    rname = data['rule_path']
    tname = data['test_path']
    tests = data['splited_testsuite_b']
    example_set = semgrep_pipeline.prepare_data(data)
    pset =  [e for e in example_set if e.ok() and e.expect]
    nset =  [e for e in example_set if e.ok() and not e.expect]
    incorrects = [e for e in example_set if not e.ok()]
    logging.debug(f"pset: {len(pset)}")
    logging.debug(f"nset: {len(nset)}")
    logging.debug(f"fnset: {len(incorrects)}")

    incorrect = incorrects[0]
    logging.info(f"incorrect: \n{incorrect.content}")

    for p in pset:
        logging.info(f"positive: \n{p.content}")

    for p in nset:
        logging.info(f"negative: \n{p.content}")

    # localization
    localizations = lcp_locate(rule, nset, incorrect)
    localizations = localizations
    expl_id = {}
    for loc in localizations:
        d1, d2 = graph.diff(loc[2], loc[3])
        fact = graph.get_fact(incorrect.graph, d1[0])
        if fact['id'] not in expl_id:
            expl_id[fact['id']] = fact
            print("locate to expl id: ", fact['id'])
            print("locate to expl op: ", fact['op'])
            print("locate to ast: ", incorrect.am[incorrect.m[fact['id']]])
motivation_example()
    

        

