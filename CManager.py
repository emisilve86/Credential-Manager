#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# This file is part of the emisilve86 distribution (https://github.com/emisilve86).
# Copyright (c) 2022 Emiliano Silvestri.
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import os
import sys
import json
import datetime

from threading import Thread, Event

from ManagerUI.manager_ui import *
from ManagerCrypto.manager_crypto import *


FILENAME = 'cm.data'
NEWFILECONTENT = '{ "data": { "service": { }, "username": { } } }'


def thread_encryption_function(path, data, password, running):
	inflated_data = inflate_short_data(data)
	encrypt_file_content(path, inflated_data, password)
	running.set()


def thread_decryption_function(path, password, result, running):
	raw_data = decrypt_file_content(path, password)
	if raw_data:
		result.append(deflate_long_data(raw_data))
	running.set()


def background_encryption(path, data, password):
	running = Event()
	encrypter = Thread(target=thread_encryption_function, args=(path, data, password, running,))
	encrypter.start()
	show_progress_background_work('Encryption may take some time. Please wait.', running)
	encrypter.join()


def background_decryption(path, password):
	result = []
	running = Event()
	decrypter = Thread(target=thread_decryption_function, args=(path, password, result, running,))
	decrypter.start()
	show_progress_background_work('Decryption may take some time. Please wait.', running)
	decrypter.join()
	return result.pop() if result else None


def check_password_file(file):
	cwd = os.getcwd()
	if not os.path.exists(os.path.join(cwd, file)):
		return False
	elif not os.path.isfile(os.path.join(cwd, file)):
		return False
	return True


def check_tmp_password_file(file):
	cwd = os.getcwd()
	if not os.path.exists(os.path.join(cwd, '~{0}'.format(file))):
		return False
	elif not os.path.isfile(os.path.join(cwd, '~{0}'.format(file))):
		return False
	return True


def create_encrypted_password_file(file):
	if not show_request_message('A file holding credentials does not exist yet. Do you want to create it?'):
		return
	password = insert_password(True)
	if not password:
		return
	cwd = os.getcwd()
	background_encryption(os.path.join(cwd, file), NEWFILECONTENT, password)
	if os.path.exists(os.path.join(cwd, '~{0}'.format(file))):
		os.remove(os.path.join(cwd, '~{0}'.format(file)))
	show_info_message('The file holding credentials has been created.')


def recover_encrypted_password_file(file, message):
	if show_request_message(message):
		cwd = os.getcwd()
		if os.path.exists(os.path.join(cwd, file)):
			if not show_request_message('By pressing YES you agree to proceed. Are you sure you want to continue?'):
				return
		os.replace(os.path.join(cwd, '~{0}'.format(file)), os.path.join(cwd, file))


def show_update_encrypted_password_file(file):
	if not check_password_file(file):
		if not check_tmp_password_file(file):
			create_encrypted_password_file(file)
		else:
			recover_encrypted_password_file(file, "A file holding credentials does not exist yet. "
				"Anyhow, a temporary image is present. This could be occurred due to, e.g., power loss or USB removal. "
					"Do you want to recover it?")
		return
	password = insert_password(False)
	if not password:
		return
	cwd = os.getcwd()
	data = background_decryption(os.path.join(cwd, file), password)
	if data is None:
		if not check_tmp_password_file(file):
			show_error_message('The password provided is wrong or the file is corrupted.')
		else:
			recover_encrypted_password_file(file, "The password provided is wrong or the file is corrupted. "
				"Anyhow, a temporary image is present. If you are confident to know your password, then push NO and try again. "
					"Otherwise, push YES to recover it.")
		return
	json_data = json.loads(data)
	if not json_data:
		if not check_tmp_password_file(file):
			show_error_message('The file holding credentials is corrupted.')
		else:
			recover_encrypted_password_file(file, "The file holding credentials is corrupted. "
				"Anyhow, a temporary image is present. If you desire to recover it, then push YES. "
					"Note that the main file will be overwritten.")
		return
	json_data_updated = show_data(json_data)
	if not json_data_updated:
		return
	raw_data_updated = json.dumps(json_data_updated)
	if not raw_data_updated:
		return
	os.replace(os.path.join(cwd, file), os.path.join(cwd, '~{0}'.format(file)))
	background_encryption(os.path.join(cwd, file), raw_data_updated, password)
	if os.path.exists(os.path.join(cwd, '~{0}'.format(file))):
		os.remove(os.path.join(cwd, '~{0}'.format(file)))
	show_info_message('The file holding credentials has been updated.')


def export_backup_password_file(file):
	if not check_password_file(file):
		if not check_tmp_password_file(file):
			show_error_message('A file holding credentials does not exist yet. Push "Open" or "Import" to create a new one.')
		else:
			recover_encrypted_password_file(file, "A file holding credentials does not exist yet. "
				"Anyhow, a temporary image is present. This could be occurred due to, e.g., power loss or USB removal. "
					"Do you want to recover it?")
		return
	password = insert_password(False)
	if not password:
		return
	cwd = os.getcwd()
	data = background_decryption(os.path.join(cwd, file), password)
	if not data:
		if not check_tmp_password_file(file):
			show_error_message('The password provided is wrong or the file is corrupted.')
		else:
			recover_encrypted_password_file(file, "The password provided is wrong or the file is corrupted. "
				"Anyhow, a temporary image is present. If you are confident to know your password, then push NO and try again. "
					"Otherwise, push YES to recover it.")
		return
	backup_directory = export_backup()
	if not backup_directory:
		return
	if show_request_message('Do you want to use a different password for the backup file?'):
		password = None
		password = insert_password(True)
		if not password:
			return
	background_encryption(os.path.join(backup_directory, datetime.datetime.now().strftime('cm_%Y%m%d_%H%M%S.bak')), data, password)
	show_info_message('The backup file was exported successfully.')


def import_backup_password_file(file):
	if check_password_file(file):
		if not show_request_message('A file holding credentials already exists. Do you want to overwrite its content?'):
			return
	backup_file = import_backup()
	if not backup_file:
		return
	password = insert_password(False)
	if not password:
		return
	data = background_decryption(backup_file, password)
	if not data:
		if not check_tmp_password_file(file):
			show_error_message('The password provided is wrong or the file is corrupted.')
		else:
			recover_encrypted_password_file(file, "The password provided is wrong or the file is corrupted. "
				"Anyhow, a temporary image is present. If you are confident to know your password, then push NO and try again. "
					"Otherwise, push YES to recover it.")
		return
	if show_request_message('Do you want to use a different password for the imported file?'):
		password = None
		password = insert_password(True)
		if not password:
			return
	cwd = os.getcwd()
	background_encryption(os.path.join(cwd, file), data, password)
	show_info_message('The backup file was imported successfully.')


def update_master_password(file):
	if not check_password_file(file):
		if not check_tmp_password_file(file):
			show_error_message('A file holding credentials does not exist yet. Push "Open" or "Import" to create a new one.')
		else:
			recover_encrypted_password_file(file, "A file holding credentials does not exist yet. "
				"Anyhow, a temporary image is present. This could be occurred due to, e.g., power loss or USB removal. "
					"Do you want to recover it?")
		return
	password = insert_password(False)
	if not password:
		return
	cwd = os.getcwd()
	data = background_decryption(os.path.join(cwd, file), password)
	if not data:
		if not check_tmp_password_file(file):
			show_error_message('The password provided is wrong or the file is corrupted.')
		else:
			recover_encrypted_password_file(file, "The password provided is wrong or the file is corrupted. "
				"Anyhow, a temporary image is present. If you are confident to know your password, then push NO and try again. "
					"Otherwise, push YES to recover it.")
		return
	password = None
	password = insert_password(True)
	if not password:
		return
	os.replace(os.path.join(cwd, file), os.path.join(cwd, '~{0}'.format(file)))
	background_encryption(os.path.join(cwd, file), data, password)
	if os.path.exists(os.path.join(cwd, '~{0}'.format(file))):
		os.remove(os.path.join(cwd, '~{0}'.format(file)))
	show_info_message('The password used to encrypt the credentials was updated successfully.')


if __name__ == '__main__':
	while (True):
		action = choose_action()
		if action == Action.OPEN:
			show_update_encrypted_password_file(FILENAME)
		elif action == Action.EXPORT:
			export_backup_password_file(FILENAME)
		elif action == Action.IMPORT:
			import_backup_password_file(FILENAME)
		elif action == Action.UPDATE:
			update_master_password(FILENAME)
		elif action == Action.EXIT:
			sys.exit()
		else:
			sys.exit()