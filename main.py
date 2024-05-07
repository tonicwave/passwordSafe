# Christopher Blum
# Oregon State ONID: 934495433
# blumch@oregonstate.edu
# passwordSafe
# version 0.1

import random
import time
import datetime
import pickle

# global strings
LOOKUP_PROMPT = "Enter the nickname of the account to update: "
USERNAME_PROMPT = "Enter a username []: "
PASSWORD_PROMPT = "Enter a password []: "
NICKNAME_PROMPT = "Enter a nickname for this account (e.g. OSU): "
WEBSITE_PROMPT = "Enter a website for this account []: "
NOTES_PROMPT = "Enter your notes about this account []: "
NOT_FOUND_PROMPT = "\nSorry. No such account found with that nickname.\n"
CREDENTIALS_SAVED = "\nCredentials saved.\n"
NOTE_SAVED = "\nNote saved.\n"
MENU_PROMPT = "New (n)\nUpdate (u)\nAdd Note (a)\nQuit (q)\nHelp (h)\n\t\tpSafe>   "


class Credentials:
    def __init__(self, nickname=None, username=None, password=None, website=None):
        self.nickname = nickname
        self.username = username
        self.password = password
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

    def set_password(self, new_password):
        self.password = new_password
        self.password_history[datetime.datetime.now()] = self.password

    def get_password(self):
        return self.password

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

    def get_current_credentials(self):
        return self.website, self.username, self.password

    def add_note(self, new_note):
        self.notes = new_note
        self.notes_history[datetime.datetime.now()] = self.notes

    def print_notes_history(self):
        for key, value in self.notes_history.items().__reversed__():
            print(f'{value}')


class PasswordSafe:
    def __init__(self, safe_file_name=None):
        self.credentials = {}
        self.safe_file_name = safe_file_name
        if self.safe_file_name is not None:
            self.read_safe()

    def add_credential(self, new_credential):
        self.credentials[new_credential.get_nickname().lower()] = new_credential

    def print_all_credentials(self):
        for key, value in self.credentials.items():
            (cur_web, cur_name, cur_pwd) = value.get_current_credentials()
            print(f'{key}: {cur_web} {cur_name} {cur_pwd}')

    def delete_credential(self, existing_credential):
        try:
            self.credentials.pop(existing_credential.get_nickname().lower())
        except KeyError:
            pass

    def save_safe(self):
        if self.safe_file_name is not None:
            with open(self.safe_file_name, 'wb') as safe_file:
                pickle.dump(self.credentials, safe_file)

    def read_safe(self):
        with open(self.safe_file_name, 'rb') as safe_file:
            self.credentials = pickle.load(safe_file)

    def lookup_by_nickname(self, nick_name):
        try:
            return self.credentials[nick_name.lower()]
        except KeyError:
            return None


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
        print('\n\nWelcome to passwordSafe!\npasswordSafe lets you store all your passwords in one secure place\n'
              '\nNOTE: Your passwords are stored locally on your \n\t'
              'computer and will take up space and are subject\n\t'
              'to all the risks associated with storing local files.\n\t'
              'You may want to consider a cloud backup of your safe.\n\n')

    def print_menu(self):
        print('OPTIONS')
        print('\tType "new" to enter a new set of credentials (shortcut: n)')
        print('\tType "update" to save a password to an existing set of credentials (shortcut: u)')
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
        credential = self.lookup_account()
        if credential is None:
            print(NOT_FOUND_PROMPT)
        else:
            new_password = self.read_input(PASSWORD_PROMPT)
            credential.set_password(new_password)
            self.passwordSafe.add_credential(credential)
            print(CREDENTIALS_SAVED)

    def lookup_account(self):
        nickname = self.read_input(LOOKUP_PROMPT)
        return self.passwordSafe.lookup_by_nickname(nickname)

    def store_new_credentials(self):
        self.passwordSafe.add_credential(Credentials(self.read_input(NICKNAME_PROMPT),
                                                     self.read_input(USERNAME_PROMPT),
                                                     self.read_input(PASSWORD_PROMPT),
                                                     self.read_input(WEBSITE_PROMPT)))
        print(CREDENTIALS_SAVED)

    def add_notes(self):
        credential = self.lookup_account()
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
        while True:
            self.print_menu()
            user_input = self.read_input(MENU_PROMPT).lower()
            if user_input == 'q' or user_input == 'quit':
                break
            else:
                self.process_user_command(user_input)
        self.passwordSafe.save_safe()

    def process_user_command(self, user_input):
        if user_input == 'u' or user_input == 'update':
            self.store_new_password()
        elif user_input == 'n' or user_input == 'new':
            self.store_new_credentials()
        elif user_input == 'a' or user_input == 'add':
            self.add_notes()
        elif user_input == 'h' or user_input == '?' or user_input == 'help':
            self.print_help()


if __name__ == '__main__':
    safe = PasswordSafe("safe.dat")
    ui = SafeTextUI(safe)
    safe.print_all_credentials()
