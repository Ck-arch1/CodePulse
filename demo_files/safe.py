def normalize_name(name):
    return name.strip().lower()


def greet_user(name):
    safe_name = normalize_name(name)
    return f"hello {safe_name}"
