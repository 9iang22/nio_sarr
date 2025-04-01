class Counter():
    def __init__(self):
        self.i = 0

    def __next__(self):
        self.i += 1
        return self.i

    def __iter__(self):
        return self
    