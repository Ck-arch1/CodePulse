def read_expression():
    return input("expression> ")


def evaluate_expression():
    expression = read_expression()
    return eval(expression)
