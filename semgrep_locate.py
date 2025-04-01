import semgrep2nx
from example import Example
from typing import List
from semgrep import semgrep_explanation_in_tempdir
import json
from utils import Counter
import graph
import math
import logging

debug = True

def spfl(rule, set: List[Example], e:Example):
    assert not e.ok()
    # 1. get G for each example first
    for s in set + [e]:
        output, error = semgrep_explanation_in_tempdir(rule, s.content, s.rname, s.tname)
        outjson = json.loads(output)
        st, ed, s.graph = semgrep2nx.Semgrep2NX(outjson['explanations'][0], Counter())
    # 3. build spectrum for each example
    ef = {n:0 for n in e.graph.nodes}
    nf = {n:0 for n in e.graph.nodes}
    ep = {n:0 for n in e.graph.nodes}
    np = {n:0 for n in e.graph.nodes}
    for s in set:
        for n in s.graph.nodes:
            if semgrep2nx.is_true(s.graph, n):
                ep[n] += 1
            else:
                np[n] += 1
                
    for n in e.graph.nodes:
        if semgrep2nx.is_true(e.graph, n):
            ef[n] += 1
        else:
            nf[n] += 1
    # 4. find the most suspicious node
    def ochiai(ef, nf, ep, np): return ef / math.sqrt((ef + nf)*(ef + ep))
    def dstar(ef, nf, ep, np): return ef*ef / (nf+ep)
    def tarantula(ef, nf, ep, np): return ef / (ef + nf) / (ef / (ef + nf) + ep / (ep + np))
    def naish1(ef, nf, ep, np): return -1 if nf > 0 else np
    def jaccard(ef, nf, ep, np): return ef / (ef + nf + ep)

    suspicious = [(n, ochiai(ef[n], nf[n], ep[n], np[n])) for n in e.graph.nodes]
    suspicious = sorted(suspicious, key=lambda x: x[1], reverse=True)
    return suspicious


def empty_explanations(rule, example_set : List[Example], e : Example):
    for s in example_set + [e]:
        output, error = semgrep_explanation_in_tempdir(rule, s.content, s.rname, s.tname)
        outjson = json.loads(output)
        if "explanations" not in outjson:
            continue
        def __empty(expl):
            expl['matches'] == []
            expl['children'] == [__empty(c) for c in expl['children']]
            return expl
        outjson['explanations'] = [__empty(outjson['explanations'][0])]
        return outjson
    return None


def lcp_locate(rule, example_set : List[Example], e : Example):
    logging.debug(f"lcp_locate: {e.rname} {len(example_set)}")
    # 1. get G for each example first
    for s in example_set + [e]:
        output, error = semgrep_explanation_in_tempdir(rule, s.content, s.rname, s.tname)
        outjson = json.loads(output)
        if "explanations" not in outjson:
            # happens when none of the patterns match the example
            outjson = empty_explanations(rule, example_set, e)
            if not outjson:
                # unlikely
                raise Exception("empty_explanations failed, need check")
        ast = semgrep2nx.yaml2ast(rule)
        ast = semgrep2nx.trans(ast)[0]
        m, am, em, ast, expl = semgrep2nx.align(outjson['explanations'][0], ast)
        s.m = m
        s.am = am
        s.em = em
        s.ast = ast
        s.expl = expl
        s.st, s.ed, s.graph = semgrep2nx.Semgrep2NX(outjson['explanations'][0], Counter())
        # 2. get all pathes from each G
        pathes = graph.find_all_paths(s.graph, semgrep2nx.is_true)
        s.path = pathes
    # 3. find longest common path for each pair of (e, e')
    # if debug:
    #     from pyvis.network import Network
    #     net = Network(notebook=False, directed=True)
    #     net.from_nx(e.graph)
    #     net.save_graph("debug.html")
    lcp_results = []
    for s in example_set:
        for p in s.path:
            for p2 in e.path:
                i, j = graph.lcp(p2, p)
                d1, _ = graph.diff(p2, p)
                if d1:
                    lcp_results.append([i, j, p2, p])
    lcp_results = sorted(lcp_results, key=lambda x: x[0], reverse=True)

    new_results = []
    for i, r in enumerate(lcp_results):
        if i == 0:
            new_results.append(r)
            continue
        if r == lcp_results[i-1]:
            continue
        new_results.append(r)
    lcp_results = new_results
    return lcp_results

def test():
    import json
    data = json.load(open("examples/localization.json"))
    rule = data['rule']
    rname = data['rule_path']
    tname = data['test_path']
    pset = [data['splited_testsuite_b'][0]]
    nset = data['splited_testsuite_b'][1:3]
    e = data['splited_testsuite_b'][3]
    nset = [Example(tname, rname, p, "semgrep", False, False) for p in nset]
    e = Example(tname, rname, e, "semgrep", False, True)
    #print(spfl(rule, nset, e))
    locations = lcp_locate(rule, nset, e)
    for enode, anode in e.m.items():
        print(f"match : {e.em[enode]['op']} -> {e.am[anode]['op']}")
    
    for loc in locations:
        d1, d2 = graph.diff(loc[2], loc[3])
        print(d1)
        fact = graph.get_fact(e.graph, d1[0])
        print("locate to expl id: ", fact['id'])
        print("locate to expl op: ", fact['op'])
        print("locate to ast: ", e.am[e.m[fact['id']]])

def bug():
    import json
    data = json.load(open("examples/bug.json"))
    rule = data['rule']
    rname = data['rule_path']
    tname = data['test_path']
    pset = data['splited_testsuite_b'][1:3]
    nset = data['splited_testsuite_b'][3:5]
    e = data['splited_testsuite_b'][5]
    nset = [Example(tname, rname, p, "semgrep", False, False) for p in nset]
    e = Example(tname, rname, e, "semgrep", False, True)
    #print(spfl(rule, nset, e))
    locations = lcp_locate(rule, nset, e)
    for enode, anode in e.m.items():
        print(f"match : {e.em[enode]['op']} -> {e.am[anode]['op']}")
    

    for loc in locations[:5]:
        print(loc)
        d1, d2 = graph.diff(loc[2], loc[3])
        if d1 is None:
            continue
        fact = graph.get_fact(e.graph, d1[0])
        print("locate to expl id: ", fact['id'])
        print("locate to expl op: ", fact['op'])
        print("locate to ast: ", e.am[e.m[fact['id']]])

def test_empty_expl():
    import json
    data = json.load(open("examples/bug.json"))
    rule = data['rule']
    rname = data['rule_path']
    tname = data['test_path']
    pset = data['splited_testsuite_b'][1:3]
    nset = data['splited_testsuite_b'][3:5]
    e = data['splited_testsuite_b'][5]
    nset = [Example(tname, rname, p, "semgrep", False, False) for p in nset]
    e = Example(tname, rname, e, "semgrep", False, True)
    outjson = empty_explanations(rule, nset, e)
    print(outjson)


if __name__ == "__main__":
    test()
    bug()