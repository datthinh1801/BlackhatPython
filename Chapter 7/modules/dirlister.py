import os


def run(**args) -> str:
    """
    List files in current directory.
    """
    print("[+] In dirlister module.")
    files = os.listdir('.')
    return str(files)
