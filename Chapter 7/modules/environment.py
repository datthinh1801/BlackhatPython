import os


def run(**args):
    """
    Return environment variables on the remote machine.
    """
    print("[+] In environment module.")
    return str(os.environ)
