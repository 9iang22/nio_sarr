class Example:
    def __init__(self, tname, rname, content, engine, expect, actual, class_name=None, method_name=None, lang=None):
        self.tname = tname
        self.rname = rname
        self.content = content
        self.engine = engine
        self.expect = expect
        self.actual = actual
        self.class_name = class_name
        self.method_name = method_name
        self.lang = lang
    
    def ok(self):
        return self.actual == self.expect
    
    def positive(self):
        return self.expect == True
    
    def negative(self):
        return self.expect == False
    
    def is_fp(self):
        return self.expect == False and self.actual == True
    
    def is_fn(self):
        return self.expect == True and self.actual == False
    
    def __repr__(self):
        return f"expected {self.expect} actual {self.actual}"