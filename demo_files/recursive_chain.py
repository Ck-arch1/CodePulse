def unsafe(value):
    return eval(value)


def recursive(value, depth):
    if depth <= 0:
        return unsafe(value)
    return recursive(value, depth - 1)


def cycle_a(value):
    return cycle_b(value)


def cycle_b(value):
    return cycle_a(value)
