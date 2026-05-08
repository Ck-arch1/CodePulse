def source_value():
    return input("value> ")


def layer_1():
    return source_value()


def layer_2():
    return layer_1()


def layer_3():
    return layer_2()


def layer_4():
    return layer_3()


def layer_5():
    return layer_4()


def execute_expression():
    value = layer_5()
    return eval(value)
