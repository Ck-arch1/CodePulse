import os
import subprocess


def get_host():
    return input("host> ")


def ping_host():
    host = get_host()
    os.system("ping " + host)


def list_directory(path):
    subprocess.run("dir " + path, shell=True)
