import concurrent.futures
import tqdm

def example_map_function(item):
    # Define the mapping function that will be applied to each element
    # For example, square each element
    return item ** 2

def example_reduce_function(mapped_items):
    # Define the reducing function that will be applied to the mapped results
    # For example, sum all squared results
    return sum(mapped_items)

def map_reduce(data, map_func, reduce_func, max_workers=None):
    # Use a thread pool to execute the mapping operations concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit mapping tasks and keep the original data indices
        futures = {executor.submit(map_func, item): index for index, item in enumerate(data)}
        
        # Collect the mapped results and sort them according to the original order
        mapped_results = [None] * len(data)
        for future in tqdm.tqdm(concurrent.futures.as_completed(futures)):
            index = futures[future]
            mapped_results[index] = future.result()
    
    # Execute the reducing operation
    reduced_result = reduce_func(mapped_results)
    
    return reduced_result

if __name__ == "__main__":
    # Example data
    data = [1, 3, 5, 7, 9, 2, 4, 6, 8]
    # Execute MapReduce
    result = map_reduce(data, example_map_function, example_reduce_function, max_workers=4)
    print("Final result:", result)

    data = ["1+1=", "hello", "write a python func"]
    def mapf(prompt):
        from deepseek import chat
        return chat(prompt)

    def reducef(mapped_items):
        return mapped_items
    
    result = map_reduce(data, mapf, reducef, max_workers=3)
    print("deepseek result :", result)