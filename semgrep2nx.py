import networkx as nx
from utils import Counter
import yaml
from utils import Counter
from functools import reduce
import logging

all = {
    "pattern" : [["XPat", "ANY"]],
    "pattern-not" : ["Negation", ["XPat", "ANY"]],
    "pattern-inside" : ["Inside", ["XPat", "ANY"]],
    "pattern-not-inside" : ["Negation", "Inside", ["XPat", "ANY"]],
    "patterns": ["And"],
    "pattern-either": ["Or"],
    "pattern-sinks": ["TaintSink"],
    "pattern-sources": ["TaintSource"],
    "pattern-sanitizers": ["TaintSanitizer"],
    "pattern-propagators": ["TaintPropagator"], # pro engine, may no use
    "pattern-regex": [["XPat", "ANY"]],
    "pattern-not-regex": ["Negation", ["XPat", "ANY"]],
    "focus-metavariable": [["Filter","metavariable-focus"]],
    "metavariable-regex": [["Filter","\"metavariable-regex\""]],
    "metavariable-pattern": [["Filter","\"metavariable-pattern\""]],
    "metavariable-comparison": [["Filter","\"metavariable-comparison\""]],
    "metavariable-analysis" : [["Filter","\"metavariable-comparison\""]],
    "taint": ["Taint"], # import by gen_semgrep_pathes
}

leaf = {
    "pattern" : [["XPat", "ANY"]],
    "pattern-not" : ["Negation", ["XPat", "ANY"]],
    "pattern-inside" : ["Inside", ["XPat", "ANY"]],
    "pattern-not-inside" : ["Negation", "Inside", ["XPat", "ANY"]],
    "pattern-regex": [["XPat", "ANY"]],
    "pattern-not-regex": ["Negation", ["XPat", "ANY"]],
    "focus-metavariable": [["Filter","metavariable-focus"]],
    "metavariable-regex": [["Filter","\"metavariable-regex\""]],
    "metavariable-pattern": [["Filter","\"metavariable-pattern\""]],
    "metavariable-comparison": [["Filter","\"metavariable-comparison\""]],
    "metavariable-analysis" : [["Filter","\"metavariable-comparison\""]],
}

def yaml2match(kv):
    key = kv['op']
    k = key
    if isinstance(k, list):
        k = key[0]
        v = key[1]
    else:
        v = None
    mapping = {
        "pattern" : [["XPat", v]],
        "pattern-not" : ["Negation", ["XPat", v]],
        "pattern-inside" : ["Inside", ["XPat", v]],
        "pattern-not-inside" : ["Negation", "Inside", ["XPat", v]],
        "patterns": ["And"],
        "pattern-either": ["Or"],
        "pattern-sinks": ["Taint", "TaintSink"],
        "pattern-sources": ["Taint", "TaintSource"],
        "pattern-sanitizers": ["Taint", "TaintSanitizer"],
        "pattern-regex": [["XPat", v]],
        "pattern-not-regex": ["Negation", ["XPat", v]],
        "focus-metavariable": [["Filter","metavariable-focus"]],
        "metavariable-regex": [["Filter","\"metavariable-regex\""]],
        "metavariable-pattern": [["Filter","\"metavariable-pattern\""]],
        "metavariable-comparison": [["Filter","\"metavariable-comparison\""]],
        "metavariable-analysis" : [["Filter","\"metavariable-comparison\""]],
        }
    return mapping[k]

def yaml2ast(rule):
    ast = yaml.safe_load(rule)
    return ast

def ast2yaml(ast):
    return yaml.dump(ast)

def trans(d):
    if not isinstance(d, dict):
        return d
    res = []
    for k, v in d.items():
        if not isinstance(v, list):
            res.append({"op": [k, v], "children": []})
            continue
        res.append({"op": k, "children": [trans(c) for c in v]})
    return res

def trans_back(d):
    if isinstance(d, list):
        res = {}
        for c in d:
            if not isinstance(c, dict):
                raise Exception("Unknown type")
            k, v = trans_back(c)
            res[k] = v
        return res
    if isinstance(d, str):
        return d
    if isinstance(d, dict):
        if d['children'] == []:
            return d['op'][0], d['op'][1]
        return d['op'], [trans_back(c) for c in d['children']]
    raise Exception("Unknown type")[0]

def gen_semgrep_pathes(yaml):
    # default one rule in yaml
    tags = yaml['children'][0]
    tpl = [t for t in tags if t['op'] in ["pattern", "patterns", "pattern-either", "pattern-regex", 
                                          "pattern-sinks", "pattern-sources", "pattern-sanitizers"]]
    tpl += [t for t in tags if isinstance(t['op'],list) and t['op'][0] == 'pattern']
    
    logging.debug(f"tpl: {[t['op'] for t in tpl]}")
    def listall(p, path):
        if isinstance(p, list):
            return reduce(list.extend, [listall(c, path) for c in p])
        label = p['op']
        children = p['children']
        if isinstance(label, list):
            return [path + [p]]
        if label in leaf:
            return [path + [p]]
        if label not in all:
            logging.warning(f"Unknown label {label}")
            return []

        result = []
        path = path + [p]
        for c in children:
            result += listall(c, path)
        return result
    pathes = []
    for t in tpl:
        pathes += listall(t, [])
    return [p for p in pathes if p != []]

def pathstr(p):
    return "\n->\n".join([str(x) for x in p])

def label(root, m, counter):
    if isinstance(root, list):
        return [label(c, m, counter) for c in root]
    if not isinstance(root, dict):
        return root
    root['children'] = [label(c, m, counter) for c in root['children']]
    id = next(counter)
    root['id'] = id
    m[id] = root
    return root

def align(expl, ast):
    m = {}
    am = {}
    ast = label(ast, am, Counter())
    em = {}
    expl = label(expl, em, Counter())
    pathes = gen_semgrep_pathes(ast)
    for p in pathes:
        do_match(p, [], expl, m, am, em)
    # verify
    for e, a in m.items():
        assert e in em and a in am
    return m, am, em, ast, expl


"""
    path -> ["patterns": ["pattern": "{...}"], "pattern": "{...}"]
    expl -> {"op": "And", "children": [{"op": ["XPat", "{...}"]}, {"op": ["XPat", "[...]"]}]}
"""
def do_match(path, to_match, expl, m, am, em):
    if path == [] and to_match == []:
        return True
    if to_match == []:
        to_match = yaml2match(path[0])
    logging.debug(f"expl : {expl['op']}\npath 0: {to_match[0]}")
    if expl['op'] != to_match[0]:
        return False
    
    logging.debug(f"match : {expl['op']} -> {path[0]['op']}")
    to_match = to_match[1:]
    
    if to_match == []:
        if expl['children'] == [] and path[1:] == []:
            m[expl['id']] = path[0]['id']
            return True
        matched_children = [c for c in expl['children'] if do_match(path[1:], to_match, c, m, am, em)]
    else:
        matched_children = [c for c in expl['children'] if do_match(path, to_match, c, m, am, em)]
    
    if matched_children != []:
        assert 'ast' not in expl or expl['ast'] == path[0]
        if "id" not in path[0]:
            assert False, f"Path {path[0]} has no id"
        m[expl['id']] = path[0]['id']
        return True
    return False
    

def expl2str(expl):
    return str(expl['op'])

def simplfiy(G, start, end):
    labels = nx.get_node_attributes(G, 'label')

    def is_empty(node):
        return (labels.get(node) == "Start" and node != start) or (labels.get(node) == "End" and node != end)
    
    work = 1
    while work == 1:
        rm = []
        add = []
        work = 0
        for node in list(G.nodes):
            for succ in list(G.successors(node)):
                if is_empty(succ):
                    if G.in_degree(succ) == 1:
                        for succ_2 in list(G.successors(succ)):
                            G.add_edge(node, succ_2)
                        G.remove_node(succ)
                        work = 1; break
            if work : break
            for pred in list(G.predecessors(node)):
                if is_empty(pred):
                    if G.out_degree(pred) == 1:
                        for pred_2 in list(G.predecessors(pred)):
                            G.add_edge(pred_2, node)
                        G.remove_node(pred)
                        work = 1; break
            if work : break
    for node in list(G.nodes):
        if G.in_degree(node) == 0 and G.out_degree(node) == 0:
            G.remove_node(node)
    return G

def color(G, st, ed):
    labels = nx.get_node_attributes(G, 'label')
    facts = nx.get_node_attributes(G, 'fact')
    colors = nx.get_node_attributes(G, 'color')

    def is_positive(node): 
        return (facts[node]['matches'] != []) ^ facts[node]['sanitizer']

    for node in list(G.nodes):
        if node == st or node == ed:
            colors[node] = "#FF4500"
        elif is_positive(node):
            colors[node] = "green"
        else:
            colors[node] = "grey"
    nx.set_node_attributes(G, colors, 'color')
    return G

def labelize(expl):
    result = ""
    if expl['op'] == "Inside":
        return f"Inside-{labelize(expl['children'][0])}"
    elif expl['op'] == "Negation":
        return f"Not-{labelize(expl['children'][0])}"
    else:
        if isinstance(expl['op'], str):
            result += f"{expl['op']}"
        else:
            return "-".join(expl['op'])

def analysis_sanitizer(expl, sanitizer=False):
    if expl['op'] == "TaintSanitizer":
        expl['sanitizer'] = True
    else:
        expl['sanitizer'] = sanitizer
    expl['children'] = [analysis_sanitizer(c, expl['sanitizer']) for c in expl['children']]
    return expl
        

def Semgrep2NX(expl, C):
    if "sanitizer" not in expl:
        expl = analysis_sanitizer(expl)
    G = nx.DiGraph()
    st = next(C)
    G.add_node(st, label="Start", fact=expl, color='grey')
    ed = next(C)
    G.add_node(ed, label="End", fact=expl, color='grey')
    G.add_edge(st, ed)

    def is_leaf(expl): return "XPat" in expl['op'] or "Negation" in expl['op'] or "Inside" in expl['op'] or "Filter" in expl['op']
    def is_and(expl): return expl['op'] == "And" or expl['op'] == "Taint"
    def is_or(expl): return expl['op'] == "Or" or expl['op'] == "TaintSource" or expl['op'] == "TaintSink" or expl['op'] == "TaintSanitizer"

    if is_leaf(expl):
        c = next(C)
        G.add_node(c, label=labelize(expl), fact=expl, color="#FF6347")
        G.add_edge(c, ed)
        G.add_edge(st, c)
        G.remove_edge(st, ed)
    elif is_and(expl) or expl['sanitizer'] and is_or(expl):
        result = []
        next_connect = st
        for c in expl["children"]:
            n_pred, n_succ, g = Semgrep2NX(c, C)
            G.add_edge(next_connect, n_pred)
            G.add_edge(n_succ, ed)
            G.remove_edge(next_connect, ed)
            G = nx.compose(G, g)
            next_connect = n_succ
        G.add_edge(next_connect, ed)
    elif is_or(expl) or expl['sanitizer'] and is_and(expl):
        for child in expl['children']:
            n_pred, n_succ, g = Semgrep2NX(child, C)
            G = nx.compose(G, g)
            G.add_edge(st, n_pred)
            G.add_edge(n_succ, ed)
            if G.has_edge(st, ed):
                G.remove_edge(st, ed)
    comp = nx.weakly_connected_components(G)
    if not len(list(comp)) == 1:
        # net = Network(notebook=False, directed=True, cdn_resources='in_line')
        # net.from_nx(G)
        # net.save_graph("debug.html")
        assert False
    G = simplfiy(G,st,ed)
    return st, ed, G

def is_true(G, node):
    label = nx.get_node_attributes(G, 'label')[node]
    if label == "Start" or label == "End":
        return True
    return nx.get_node_attributes(G, 'fact')[node]['matches'] != []

def test_expr2str():
    import json
    d = json.load(open("matching_explanation_example.json"))
    str = expl2str(d['explanations'][0])
    print(str)

def test():
    import json
    from pyvis.network import Network
    d = json.load(open("matching_explanation_example.json"))
    pred, succ, G = Semgrep2NX(d['explanations'][0], Counter())
    G = simplfiy(G, pred, succ)
    G = color(G, pred, succ)
    net = Network(notebook=False, directed=True)
    net.from_nx(G)
    net.save_graph("semgrep2nx.html")

def cli():
    import json
    import sys
    from pyvis.network import Network
    d = json.load(open(sys.argv[1]))
    pred, succ, G = Semgrep2NX(d['explanations'][0], Counter())
    G = simplfiy(G, pred, succ)
    G = color(G, pred, succ)
    net = Network(notebook=False, directed=True)
    net.from_nx(G)
    net.show_buttons(filter_=['physics','layout'])
    net.save_graph("semgrep2nx.html")

if __name__ == "__main__":
    # test()
    # test_expr2str()
    cli()