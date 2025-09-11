TRANSFORMATIONS = {}


def register_transformation(name):
    def decorator(fn):
        TRANSFORMATIONS[name.lower()] = fn
        return fn

    return decorator


@register_transformation("lowercase")
def lowercase(value):
    lower_val = value.lower()
    return lower_val, lower_val != value
