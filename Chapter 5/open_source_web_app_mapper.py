"""
Download an open source web framework.
Enumerate files of the framework's installation.
Create a mapping to brute-force remote files of a web app if using the framework.
"""

import contextlib
import os
import queue
import requests
import sys
import threading
import time

FILTERED = [".jpg", ".gif", ".png", ".css"]
TARGET = None
THREADS = 10

# thread-safe queue
answers = queue.Queue()
web_paths = queue.Queue()


def gather_paths():
    """Gather paths of the local web application directory to create a mapping."""
    # walk from the current directory down
    for dir_path, dir_name, filenames in os.walk("."):
        for fname in filenames:
            # splite the fname into (root, ext)
            # ext is empty if fname starts with . (e.g. .gitignore)
            # .test.txt will be ('.test', '.txt')
            if os.path.splitext(filenames)[1] in FILTERED:
                continue
            path = os.path.join(dir_path, fname)
            # if path is relative to the current directory,
            if path.startswith("."):
                path = path[1:]
            print(path)
            web_paths.put(path)


# the context manager guarantees that after we finish doing something in other directory,
# we'll moved back to the original one.
@contextlib.contextmanager
def chdir(path):
    """
    On enter, cd to the specified path.
    On exit, cd back to the original.
    """
    this_dir = os.getcwd()
    os.chdir(path)
    try:
        # this yield statement is necessary
        # to return the control back to the main thread
        yield
    finally:
        os.chdir(this_dir)


def test_remote():
    """Test local paths against the remote server."""
    # extract each path until it is emtpy
    while not web_paths.empty():
        path = web_paths.get()
        url = f"{TARGET}{path}"
        # add a gap interval to avoid being blocked
        # due to bombarding the server
        time.sleep(2)
        response = requests.get(url)
        if response.status_code == 200:
            answers.put(url)
            sys.stdout.write("+")
        else:
            sys.stdout.write("x")
        sys.stdout.flush()


def run():
    """Start brute-forcing the server."""
    my_threads = list()
    for i in range(THREADS):
        print(f"Spawning thread {i}")
        t = threading.Thread(target=test_remote)
        my_threads.append(t)
        t.start()

    for thread in my_threads:
        thread.join()


if __name__ == "__main__":
    # this with statement makes use of the context manager above
    with chdir(os.getcwd()):
        gather_paths()

    # add a pause to review the console output
    input("Press enter to continue.")

    run()
    with open("answers.txt", "w") as f:
        while not answers.empty():
            f.write(f"{answers.get()}\n")
    print("done")
