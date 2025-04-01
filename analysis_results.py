import sys
import json
import tqdm
import shutil
import os

def summary(d):
    try:
        results = ""
        results += "="*0x30 + "\n"
        results += d['id'] + "\n"
        results += "-"*0x30 + "\n"
        results += str(d['verify_result']) + "\n"
        results += "-"*0x30 + "\n"
        results += d['prompt']['prompt'] + "\n"
        results += "-"*0x30 + "\n"
        results += json.loads(d['response'])['choices'][0]['message']['content'] + "\n"
        results += "-"*0x30 + "\n"
        results += d['testsuite_a'] + "\n"
        results += "="*0x30 + "\n"
        return True, results
    except:
        return False, str(d)

def dedup(data):
    m = {}
    for d in data:
        if d['prompt']['incorrect'] not in m:
            m[d['prompt']['incorrect']] = []
        m[d['prompt']['incorrect']].append(d)
    
    cnt = 0
    for k, v in m.items():
        for e in v:
            if e['verify_result'] == ["REFINE_SUCCESS"]:
                cnt += 1
                break
    print(f"success rate: {cnt} / {len(m)} ({cnt/len(m) * 100:.2f}%)")

    for k, v in m.items():
        success = [e for e in v if e['verify_result'] == ["REFINE_SUCCESS"]]
        failed = [e for e in v if e['verify_result'] != ["REFINE_SUCCESS"]]
        print(f"{v[0]['id']}-{hash(k)%999}", len(success) != 0)

def repro(inf, outd):
    import sys
    with open(inf) as f:
        lines = f.readlines()
        data = [json.loads(line) for line in lines]
    
    if os.path.exists(outd):
        shutil.rmtree(outd)
    os.makedirs(outd)

    for i, d in tqdm.tqdm(enumerate(data)):
        cdir = os.path.join(outd, f"{i}")
        os.makedirs(cdir)
        ok, sum = summary(d)
        if not ok:
            print(sum)
            continue
        with open(os.path.join(cdir, "summary.txt"), "w") as f:
            f.write(sum)
    

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", type=str)
args = parser.parse_args()

with open(os.path.join(args.input)) as f:
    lines = f.readlines()
    data = [json.loads(line) for line in lines]
    dedup(data)