from semgrep2nx import *
import yaml
from pprint import pprint
import json
import uuid

rule = """rules:
  - id: unverified-db-query
    patterns:
      - pattern: db_query(...)
      - pattern-not: db_query(..., verify=True, ...)
    message: Found unverified db query
    severity: ERROR
    languages:
      - python
"""

rule2 = """
rules:
  - id: insecure-methods
    patterns:
      - pattern: module.$METHOD(...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: (insecure)
    message: module using insecure method call
    languages:
      - python
    severity: ERROR
"""

rule3 = """
rules:
  - id: detect-only-foo-package
    languages:
      - regex
    message: Found foo package
    patterns:
      - pattern-regex: foo
      - pattern-not-regex: foo-
      - pattern-not-regex: -foo
    severity: ERROR
"""

rule4 = """
rules:
  - id: test
    mode: taint
    pattern-sources:
      - pattern: user_input
    pattern-propagators:
      - patterns:
          - pattern: |
              if something($FROM):
                ...
                $TO()
                ...
        from: $FROM
        to: $TO
        by-side-effect: false
    pattern-sinks:
      - pattern: sink()
    message: Semgrep found a match
    languages:
      - python
    severity: WARNING
"""

rule5 = """
rules:
  - id: cacheresult-exception-taint
    mode: taint
    options:
      taint_unify_mvars: true
    pattern-sources:
      - patterns:
          - pattern: $ARG
          - pattern-inside: |
              @CacheResult(...,cachedExceptions=$EX.class,...)
              public $T $M(...,$ARG,...){
                ...
              }
    pattern-sinks:
      - patterns:
          - pattern: $X
          - pattern-inside: |
              throw new $EX(...);
    message: Found a cached exception of type $EX
    languages:
      - java
    severity: WARNING
    metadata:
      source-rule-url: https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/
"""

rule6 = """rules:
  - id: insecure-methods
    patterns:
      - pattern: module.$METHOD(...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: (insecure)
    message: module using insecure method call
    languages:
      - python
    severity: ERROR
"""

def test_yaml2ast():
    ast = yaml2ast(rule)
    ast = trans(ast)[0]
    pathes = gen_semgrep_pathes(ast)
    assert len(pathes) == 2
    ast = yaml2ast(rule2)
    ast = trans(ast)[0]
    pathes = gen_semgrep_pathes(ast)
    assert len(pathes) == 2
    ast = yaml2ast(rule3)
    ast = trans(ast)[0]
    pathes = gen_semgrep_pathes(ast)
    assert len(pathes) == 3
    ast = yaml2ast(rule4)
    ast = trans(ast)[0]
    pathes = gen_semgrep_pathes(ast)
    assert len(pathes) == 2
    ast = yaml2ast(rule5)
    ast = trans(ast)[0]
    pathes = gen_semgrep_pathes(ast)
    assert len(pathes) == 4

def test_label_ast():
    ast = yaml2ast(rule)
    ast = trans(ast)[0]
    from utils import Counter
    m = {}
    ast = label(ast, m, Counter())
    assert len(m) == 8

def test_align():
    def tc(rpath, expl):
        rule = open(rpath).read()
        ast = yaml2ast(rule)
        ast = trans(ast)[0]
        expl = json.load(open(expl))['explanations'][0]
        m, am, em, _, _ = align(expl, ast)
        return m

    rpath = "examples/disallow-old-tls-versions2.yaml"
    expl = "examples/disallow-old-tls-versions2.json"
    assert len(tc(rpath, expl)) == 3

    rpath = "examples/alias-path-traversal.yaml"
    expl = "examples/alias-path-traversal.json"
    assert len(tc(rpath, expl)) == 5

def test_trans():
    import yaml
    for r in [rule, rule2, rule3, rule4, rule5, rule6]:
      ast = yaml.safe_load(r)
      print(ast)
      ast1 = trans(ast)
      print(ast1)
      ast2 = trans_back(ast1)
      print(ast2)
      print('---'*0x20)
      assert ast == ast2

test_yaml2ast()
test_trans()
test_label_ast()
test_align()