def retry_forever(count):
    print(count)
    return retry_forever(count + 1)
