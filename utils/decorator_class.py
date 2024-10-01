import time, decimal

class DecoratorClass:
    @staticmethod
    def my_decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            total_time = end_time - start_time
            total_time = decimal.Decimal(total_time)
            total_time = round(total_time, 2)
            print(f"Total running time of {func.__name__}: {total_time} seconds")
            return result
        return wrapper