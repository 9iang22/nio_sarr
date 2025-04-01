from openai import OpenAI
import os
import logging

def chat(prompt):
    client = OpenAI(api_key=os.getenv("DS_APIKEY"), base_url="https://api.deepseek.com")
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": "You are a helpful assistant to refine semgrep rules."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=4096,
        temperature=0.0,
        stream=False
    )
    return response.choices[0].message.content

def chat2(msg):
    client = OpenAI(api_key=os.getenv("DS_APIKEY"), base_url="https://api.deepseek.com")
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=msg,
        max_tokens=4096,
        temperature=0.0,
        stream=False
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for i in range(10):
            futures.append(executor.submit(chat, "Hello"))
        for future in concurrent.futures.as_completed(futures):
            print(future.result())