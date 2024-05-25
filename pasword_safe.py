# Christopher Blum
# Oregon State ONID: 934495433
# blumch@oregonstate.edu
# passwordSafe
# version 0.1

import datetime
import pickle
import pyotp
import time
from redis_api import RedApi
import logging
from cryptography.fernet import Fernet
import json

# global logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# global strings
MASTER_PASSWORD_PROMPT = "Enter Master Password: "
LOOKUP_PROMPT = "Enter the nickname of the account to update: "
DISPLAY_PROMPT = "Enter the nickname of the account to display: "
USERNAME_PROMPT = "Enter a username []: "
PASSWORD_PROMPT = "Enter a password []: "
SEED_PROMPT = "Enter a seed []: "
NICKNAME_PROMPT = "Enter a nickname for this account (e.g. OSU): "
WEBSITE_PROMPT = "Enter a website for this account []: "
NOTES_PROMPT = "Enter your notes about this account []: "
NOT_FOUND_PROMPT = "\nSorry. No such account found with that nickname.\n"
CREDENTIALS_SAVED = "\nCredentials saved.\n"
NOTE_SAVED = "\nNote saved.\n"
MENU_PROMPT = "New (n)\nUpdate (u)\nSeed (s)\nDisplay (d)\nAdd Note (a)\nQuit (q)\nHelp (h)\n\t\tpSafe>  "

KEY_FILENAME = 'my_secret.key'
SAFE_FILENAME = 'safe.dat'
PASSWORD_KEY = "n5_lbuaAWGhe9gdv7MA5n0ZDhpZaDUtiuoHiZYXhxa0="


class Credentials:
    def __init__(self, nickname=None, username=None, password=None, seed=None, website=None):
        self.nickname = nickname
        self.username = username
        self.password = password
        self.totp = None
        self.website = website
        self.notes = None
        self.username_history = {}
        self.password_history = {}
        self.website_history = {}
        self.notes_history = {}

    def set_nickname(self, nickname):
        self.nickname = nickname

    def get_nickname(self):
        return self.nickname

    def set_username(self, new_name):
        self.username = new_name
        self.username_history[datetime.datetime.now()] = self.username

    def get_username(self):
        return self.username

    def print_username_history(self):
        for key, value in self.username_history.items().__reversed__():
            print(f'{key}: {value}')

    def set_password(self, key, new_password):
        encryptor = Encryptor()
        enc_password = encryptor.encrypt(key, new_password)
        self.password = enc_password
        self.password_history[datetime.datetime.now()] = self.password

    def get_password(self, password_key):
        decryptor = Decryptor()
        dec_password = decryptor.decrypt(password_key, self.password)
        return dec_password

    def seed_totp(self, new_seed):
        if new_seed is not None:
            return pyotp.TOTP(new_seed)
        return None

    def set_totp(self, new_seed):
        self.totp = self.seed_totp(new_seed)

    def get_totp(self):
        totp = TotpRequestor()
        return totp.get_totp(self.username, self.nickname)

    def print_password_history(self):
        for key, value in self.password_history.items().__reversed__():
            print(f'{key}: {value}')

    def set_website(self, new_website):
        self.website = new_website
        self.website_history[datetime.datetime.now()] = self.website

    def get_website(self):
        return self.website

    def print_website_history(self):
        for key, value in self.website_history.items().__reversed__():
            print(f'{key}: {value}')

    def get_current_credentials(self, password_key):
        decryptor = Decryptor()

        return (self.nickname, self.website, self.username,
                decryptor.decrypt(password_key, self.password),
                #self.password,
                self.get_totp())

    def add_note(self, new_note):
        self.notes = new_note
        self.notes_history[datetime.datetime.now()] = self.notes

    def print_notes_history(self):
        for key, value in self.notes_history.items().__reversed__():
            print(f'{value}')


class PasswordSafe:
    def __init__(self, safe_file_name=None, password_key=None):
        self.credentials = {}
        self.safe_file_name = safe_file_name
        self.key = None
        self.locked = True
        self.password_key = password_key

    def unlock_safe(self, master_password):
        """ unlocks safe and returns true if password is valid, otherwise not and false """
        if self.check_master_password(master_password):
            self.key = self.load_key(KEY_FILENAME)
            if self.safe_file_name is not None:
                self.read_safe()
                self.locked = False

    def check_master_password(self, master_password):
        auth = Authenticator()
        return auth.authenticate("alice", master_password)

    def add_credential(self, new_credential):
        self.credentials[new_credential.get_nickname().lower()] = new_credential

    def print_credential(self, creds):
        (cur_nick, cur_web, cur_name, cur_pwd, cur_totp) = creds.get_current_credentials(self.password_key)
        print(f'{cur_nick:12}{cur_web:16}\t{cur_name:20}{cur_pwd:20}{cur_totp:6}')

    def print_all_credentials(self):
        for key, value in self.credentials.items():
            self.print_credential(value)

    def delete_credential(self, existing_credential):
        try:
            self.credentials.pop(existing_credential.get_nickname().lower())
        except KeyError:
            pass

    def save_safe(self):
        if self.safe_file_name is not None:
            self.save_pickle(self.credentials, self.safe_file_name)

    def read_safe(self):
        try:
            with open(self.safe_file_name, 'rb') as safe_file:
                self.credentials = self.load_pickle(self.safe_file_name)
        except FileNotFoundError:
            print("No safe found. Starting new!")

    def lookup_by_nickname(self, nick_name):
        try:
            return self.credentials[nick_name.lower()]
        except KeyError:
            return None

    def make_key(self, key_file=None):
        with open(key_file, 'wb') as f:
            f.write(Fernet.generate_key())
        return key_file

    def load_key(self, fp: str = None):
        if fp is None:
            fp = self.make_key(KEY_FILENAME)
        with open(fp, 'rb') as f:
            return f.read()

    def load_pickle(self, fp: str) -> object:
        fernet = Fernet(self.key)
        with open(fp, 'rb') as f:
            if f is None:
                return None
            return pickle.loads(fernet.decrypt(f.read()))

    def save_pickle(self, obj: object, fp: str):
        fernet = Fernet(self.key)
        with open(fp, 'wb') as f:
            f.write(fernet.encrypt(pickle.dumps(obj)))


class SafeTextUI:

    def __init__(self, passwordSafe=None):
        self.passwordSafe = passwordSafe
        self.print_initial_screen()
        self.command_loop()

    def print_notes(self, credential):
        try:
            credential.print_notes_history()
        except AttributeError:
            print('No such credential found.')

    def print_initial_screen(self):
        while safe.locked:
            print("\nPassword Safe is locked. Enter Master Password to unlock")
            master_password = self.read_input(MASTER_PASSWORD_PROMPT)
            safe.unlock_safe(master_password)
        print('\n\nWelcome to passwordSafe!\npasswordSafe lets you store all your passwords in one secure place\n'
              '\nNOTE: Your passwords are stored locally on your \n\t'
              'computer and will take up space and are subject\n\t'
              'to all the risks associated with storing local files.\n\t'
              'You may want to consider a cloud backup of your safe.\n\n')

    def print_menu(self):
        print('OPTIONS')
        print('\tType "new" to enter a new set of credentials (shortcut: n)')
        print('\tType "update" to save a password to an existing set of credentials (shortcut: u)')
        print('\tType "display" to show a set of credentials (shortcut: d)')
        print('\tType "seed" to add a TOTP to existing credentials (shortcut: s)')
        print('\tType "add" to add a a not to an existing set of credentials (shortcut: a)')
        print('\tType "quit" to exit (shortcut: q)')
        print('\tType "help" to see the passwordSafe documentation (shortcuts: h or ?)\n')

    def print_help(self):
        print('HELP DOCUMENTATION\n\t'
              'Do not fret.\n\tpasswordSafe keeps each of your account''s information in a set of credentials.\n\t'
              'If you have never entered any credentials before, start with New (n) which lets\n\t'
              'you save a new set of credentials.\n\n\t'
              'If you need to change a password for existing credentials you have previously saved\n\t'
              'you can choose Update (u) to lookup your credentials by their nickname and then\n\t'
              'provide the new password.\n\n\t'
              'Sometimes you have information that you want to to include with credentials, like\n\t'
              'your numeric account number. You can Add a note (a) that includes such details.\n\t')

    def store_new_password(self):
        credential = self.lookup_account(LOOKUP_PROMPT)
        if credential is None:
            print(NOT_FOUND_PROMPT)
        else:
            new_password = self.read_input(PASSWORD_PROMPT)
            credential.set_password(self.passwordSafe.password_key, new_password)
            self.passwordSafe.add_credential(credential)
            print(CREDENTIALS_SAVED)

    def lookup_account(self, prompt):
        nickname = self.read_input(prompt)
        return self.passwordSafe.lookup_by_nickname(nickname)

    def display_credential(self):
        creds = self.lookup_account(DISPLAY_PROMPT)
        if creds is None:
            print(NOT_FOUND_PROMPT)
        else:
            print('\nNICKNAME\tWEBSITE\t\t\t\tUSERNAME\t\t\tPASSWORD\t\tONE-TIME PASSWORD')
            self.passwordSafe.print_credential(creds)
            print('\n')

    def store_new_credentials(self):
        self.passwordSafe.add_credential(Credentials(self.read_input(NICKNAME_PROMPT),
                                                     self.read_input(USERNAME_PROMPT),
                                                     self.read_input(PASSWORD_PROMPT),
                                                     self.read_input(WEBSITE_PROMPT)))
        print(CREDENTIALS_SAVED)

    def store_new_totp_seed(self):
        credential = self.lookup_account(LOOKUP_PROMPT)
        if credential is None:
            print(NOT_FOUND_PROMPT)
        else:
            new_seed = self.read_input(SEED_PROMPT)
            credential.set_totp(new_seed)
            self.passwordSafe.add_credential(credential)
            print(CREDENTIALS_SAVED)

    def add_notes(self):
        credential = self.lookup_account(NOTES_PROMPT)
        if credential is None:
            print(NOT_FOUND_PROMPT)
        else:
            new_notes = self.read_input(NOTES_PROMPT)
            credential.add_note(new_notes)
            self.passwordSafe.add_credential(credential)
            print(NOTE_SAVED)

    @staticmethod
    def read_input(prompt):
        return input(prompt).strip()

    def command_loop(self):
        self.print_menu()
        while True:
            user_input = self.read_input(MENU_PROMPT).lower()
            if user_input == 'q' or user_input == 'quit':
                break
            else:
                self.process_user_command(user_input)
        self.passwordSafe.save_safe()

    def process_user_command(self, user_input):
        if user_input == 'u' or user_input == 'update':
            self.store_new_password()
        if user_input == 's' or user_input == 'seed':
            self.store_new_totp_seed()
        elif user_input == 'n' or user_input == 'new':
            self.store_new_credentials()
        elif user_input == 'a' or user_input == 'add':
            self.add_notes()
        elif user_input == 'd' or user_input == 'display':
            self.display_credential()
        elif user_input == 'h' or user_input == '?' or user_input == 'help':
            self.print_help()


class RedisQue():
    def __init__(self):
        self.r = RedApi()

    def fetch_response(self, queue_name) -> dict:
        """Fetch the response from the queue, if there is one"""
        while True:
            resp = self.r.dequeue(queue_name)
            if resp:
                logger.debug(f"{queue_name} response fetched")
                return resp
            else:
                logger.debug(f"waiting for {queue_name} response...")


class TotpRequestor(RedisQue):
    def __init__(self):
        super().__init__()
        self.totp_request_queue_name = "totp_request_queue"
        self.totp_response_queue_name = "totp_response_queue"

    def enqueue_totp_request(self, username: str, nickname: str) -> bool:
        """Send a username and password to the queue

        look for a response of true if the request gets queued successfully

        message should be in the form:
        {"username": "some-username", "password": "s0m3P@ssw0rD"}
        """

        query = {"username": username, "nickname": nickname}
        self.r.enqueue(self.totp_request_queue_name, query)
        if self.r.enqueue:
            logger.info("TOTP request sent")
            return True
        else:
            logger.error("TOTP request failed")
            return False

    def totp_response(self):
        return super().fetch_response(self.totp_response_queue_name)

    def get_totp(self, username, nickname):
        result = -1
        req = self.enqueue_totp_request(username, nickname)
        if req:
            logger.debug("TOTP response waiting...")
            response = json.loads(self.totp_response())
            logger.debug(response)
            result = response[nickname]
        else:
            logger.error("Request failed")
        return result


class Authenticator(RedisQue):
    def __init__(self):
        super().__init__()
        self.auth_request_queue_name = "request_queue"
        self.auth_response_queue_name = "response_queue"

    def enqueue_auth_request(self, username: str, password: str) -> bool:
        """Send a username and password to the queue

        look for a response of true if the request gets queued successfully

        message should be in the form:
        {"username": "some-username", "password": "s0m3P@ssw0rD"}
        """

        query = {"username": username, "password": password}
        self.r.enqueue(self.auth_request_queue_name, query)
        if self.r.enqueue:
            logger.debug("Authentication request sent")
            return True
        else:
            logger.debug("Authentication request failed")
            return False

    def auth_response(self):
        return super().fetch_response(self.auth_response_queue_name)

    def authenticate(self, username, password):
        result = False
        req = self.enqueue_auth_request(username, password)
        if req:
            logger.debug("Authentication response waiting...")
            response = self.auth_response()
            logger.debug(response)
            result = response.find("True")
        else:
            logger.error("Authentication request failed")
        return result != -1


class Decryptor(RedisQue):
    def __init__(self):
        super().__init__()
        self.decrypt_request_queue_name = "decrypt_request_queue"
        self.decrypt_response_queue_name = "decrypt_response_queue"
        self.result_field = "plaintext"

    def enqueue_decrypt_request(self, key: str, ciphertext: str) -> bool:
        """Send a username and password to the queue

        look for a response of true if the request gets queued successfully

        message should be in the form:
        {"username": "some-username", "password": "s0m3P@ssw0rD"}
        """

        query = {"key": key, "ciphertext": ciphertext}
        self.r.enqueue(self.decrypt_request_queue_name, query)
        if self.r.enqueue:
            logger.info("decrypt request sent")
            return True
        else:
            logger.error("decrypt request failed")
            return False

    def decrypt_response(self) -> dict:
        return super().fetch_response(self.decrypt_response_queue_name)

    def decrypt(self, key, ciphertext):
        result = False
        req = self.enqueue_decrypt_request(key, ciphertext)
        if req:
            logger.debug("Decryption response waiting...")
            response = json.loads(self.decrypt_response())
            logger.debug(response)

            result = response[self.result_field]
        else:
            logger.error("Decryption request failed")
        return result


class Encryptor(RedisQue):
    def __init__(self):
        super().__init__()
        self.encrypt_request_queue_name = "encrypt_request_queue"
        self.encrypt_response_queue_name = "encrypt_response_queue"
        self.result_field = "ciphertext"

    def enqueue_encrypt_request(self, key: str, plaintext: str) -> bool:
        """Send a username and password to the queue

        look for a response of true if the request gets queued successfully

        message should be in the form:
        {"username": "some-username", "password": "s0m3P@ssw0rD"}
        """

        query = {"key": key, "plaintext": plaintext}
        self.r.enqueue(self.encrypt_request_queue_name, query)
        if self.r.enqueue:
            logger.info("encrypt request sent")
            return True
        else:
            logger.error("encrypt request failed")
            return False

    def encrypt_response(self) -> dict:
        return super().fetch_response(self.encrypt_response_queue_name)

    def encrypt(self, key, plaintext):
        result = False
        req = self.enqueue_encrypt_request(key, plaintext)
        if req:
            logger.debug("Encryption response waiting...")
            response = json.loads(self.encrypt_response())
            logger.debug(response)
            result = response[self.result_field]
        else:
            logger.error("Encryption request failed")
        return result


if __name__ == '__main__':
    safe = PasswordSafe(SAFE_FILENAME, PASSWORD_KEY)
    ui = SafeTextUI(safe)
    # safe.print_all_credentials()
