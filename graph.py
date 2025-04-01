import networkx as nx
from yaml import load, dump

def get_fact(G, node):
    return nx.get_node_attributes(G, 'fact')[node]

def get_label(G, node):
    return nx.get_node_attributes(G, 'label')[node]

def find_all_paths(G, is_true):
    labels = nx.get_node_attributes(G, 'label')
    def dfs(node, path):
        if labels[node] == "End":
            return [path + [(node, True)]]
        if not is_true(G, node):
            return [path + [(node, False)]]
        else:
            path = path + [(node, True)]
        res = []
        for succ in G.successors(node):
            res += dfs(succ, path)
        return res
    for k, v in labels.items():
        if v == "Start":
            start = k
            return dfs(start, [])
    raise Exception("Broken Graph")

def positive_path(path):
    for p in path:
        if not p[1]:
            return False
    return True

def negative_path(path):
    return not positive_path(path)

def lcp(p1, p2):
    def find_index(p, nodeid):
        for i, x in enumerate(p):
            if x[0] == nodeid:
                return i
        return -1
    set1 = set([x[0] for x in p1])
    set2 = set([x[0] for x in p2])
    co = set1.intersection(set2)
    max = -1
    for c in co:
        if find_index(p1, c) > max:
            max = find_index(p1, c)
    return max, find_index(p2, p1[max][0])

def diff(p1, p2):
    i, j = lcp(p1, p2)
    if p1[i][0] == p2[j][0] and p1[i][1] == p2[j][1]:
        if i + 1 < len(p1) and j + 1 < len(p2):
            return p1[i+1], p2[j+1]
        else:
            return None, None
    return p1[i], p2[j]


