try:
    from strands import tool
except ImportError:
    def tool(func):
        return func
