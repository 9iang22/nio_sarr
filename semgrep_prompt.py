def gen_prompt(rule, e, typ, mode='full'):
    if mode == 'full':
        return f"""Here is a semgrep rule to be modified, and there is an incorrect example for it. 
Please select a pattern tag from ["pattern", "pattern-not", "pattern-inside", "pattern-not-inside"] 
and add a new pattern at the <GENERATE A PATTERN HERE> position so that the entire rule can correctly classify the originally {typ} example. 
The semgrep rule to be modified is as follows:
```yaml
{rule}
```
The {typ} example is as follows:
```java
{e}
```
The answer should follow the format below:
<EXPLANATION>
YOUR_EXPLANATION_HERE
</EXPLANATION>

<FINAL_ANSWER>
```yaml
YOUR_FINAL_ANSWER_HERE
```
</FINAL_ANSWER>
"""
    if mode == 'simple':
        return f"""Here is a semgrep rule to be modified, and there is an incorrect example for it. 
The semgrep rule to be modified is as follows:
```yaml
{rule}
```
The {typ} example is as follows:
```java
{e}
```
Please modify the rule to correctly classify the originally {typ} example.
The answer should follow the format below:
<EXPLANATION>
YOUR_EXPLANATION_HERE
</EXPLANATION>

<FINAL_ANSWER>
```yaml
YOUR_FINAL_ANSWER_HERE
```
</FINAL_ANSWER>
"""

def postprocess(output):
    if "<EXPLANATION>" in output and "</EXPLANATION>" in output and "<FINAL_ANSWER>" in output and "</FINAL_ANSWER>" in output:
        start = output.index("<EXPLANATION>") + len("<EXPLANATION>")
        end = output.index("</EXPLANATION>")
        explanation = output[start:end].strip()
        start = output.index("<FINAL_ANSWER>") + len("<FINAL_ANSWER>")
        end = output.index("</FINAL_ANSWER>")
        final_answer = output[start:end].strip()
        if "```yaml" in final_answer:
            final_answer = final_answer[final_answer.index("```yaml") + len("```yaml"):]
            if "```" in final_answer:
                final_answer = final_answer[:final_answer.index("```")]
                final_answer = final_answer.strip()
        return explanation, final_answer
    return None, None