import subprocess


def get_command():
    return input("command> ")


def run_user_command():
    command = get_command()
    subprocess.Popen(command)


def controller():
    run_user_command()
