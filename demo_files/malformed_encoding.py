def decode_payload(raw):
    text = raw.decode("utf-8", errors="replace")
    return text


def main():
    payload = input("payload> ")
    return eval(payload)
