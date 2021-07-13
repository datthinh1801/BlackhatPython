import queue
import threading
import sys
import requests


AGENT = "Mozilla"
# possible extensions of configuration files
EXTENSIONS = [".php", ".bak", ".orig", ".inc"]
TARGET = None
THREADS = 50
WORDLIST = None


def get_words(resume=None) -> queue.Queue:
    """
    Read words from the WORDLIST, then extend them with some extensions.
    """

    def extend_words(word):
        """
        Intake a word, check if it is a file or a directory, and append it to the Queue.

        Then, extend that word with extensions from EXTENSIONS to
        hopefully increase the success of the brute-forcer.
        """
        # if word is a file name
        if "." in word:
            words.put(f"/{word}")
        # if word is a directory name
        else:
            words.put(f"/{word}/")

        # put all possible extensions of the name
        # if we have /admin, we extend it to
        # /admin/admin.php
        # /admin/admin.bak
        # /admin/admin.orig
        # /admin/admin.inc
        #
        # if we have /config.php, then we extend it to
        # /config.php.php
        # /config.php.bak
        # /config.php.orig
        # /config.php.inc
        for ext in EXTENSIONS:
            words.put(f"/{word}{ext}")

    ### MAIN ROUTINE ###
    with open(WORDLIST) as wordlist:
        raw_words = wordlist.read()

    found_resume = False
    words = queue.Queue()
    for word in raw_words.splitlines():
        # if resume
        if resume is not None:
            # continue from the last word
            if found_resume:
                extend_words(word)
            # found the place to resume
            elif word == resume:
                found_resume = True
                print(f"Resuming wordlist from: {resume}")
        else:
            print(word)
            extend_words(word)
    return words


def dir_bruter(words):
    """
    Brute force files and directories using words as wordlist.
    """
    headers = {"User-Agent": AGENT}
    while not words.empty():
        url = f"{TARGET}{words.get()}"
        try:
            response = requests.get(url, headers=headers)
        except requests.exceptions.ConnectionError:
            # use stderr to be able to pipe error messages to /dev/null
            sys.stderr.write("x")
            sys.stderr.flush()
            continue

        if response.status_code == 200:
            print(f"\nSuccess ({response.status_code}: {url})")
        elif response.status_code == 404:
            sys.stderr.write(".")
            sys.stderr.flush()
        else:
            print(f"{response.status_code} => {url}")


if __name__ == "__main__":
    # collect words from wordlists
    words = get_words()
    input("Press enter to continue")

    # start brute-forcing
    for _ in range(THREADS):
        t = threading.Thread(target=dir_bruter, args=(words,))
        t.start()
