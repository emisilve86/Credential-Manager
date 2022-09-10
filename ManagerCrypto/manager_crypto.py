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
import base64

from hashlib import sha3_256
from secrets import token_urlsafe
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MININFLATING = (2*(1024**2))
MININFLATEDDATA = (8*(1024**2))


def inflate_short_data(data):
	data_size = len(data.encode())
	inflating = max(data_size + MININFLATING, MININFLATEDDATA) - data_size
	leading_size = int.from_bytes(os.urandom(32), byteorder='big', signed=False) % (inflating + 1)
	trailing_size = inflating - leading_size
	inflating_data = token_urlsafe(leading_size).encode()[:leading_size]
	inflating_data += data.encode()
	inflating_data += token_urlsafe(trailing_size).encode()[:trailing_size]
	data = inflating_data.decode()
	return data


def deflate_long_data(data):
	stack_size = 0
	initial_index = 0
	final_index = 0
	scope_found = False
	for i in range(len(data)):
		if data[i] == '{':
			stack_size += 1
			if not scope_found:
				initial_index = i
				scope_found = True
		elif data[i] == '}':
			stack_size -= 1
			if stack_size == 0 and scope_found:
				final_index = i + 1
				break
	return data[initial_index:final_index]


def encrypt_file_content(path_name, raw_data, password):
	kdf = Scrypt(
		salt=sha3_256(password.encode()).digest(),
		length=32,
		n=2**20,
		r=8,
		p=1,
	)
	key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
	f = Fernet(key)
	try:
		with open(path_name, 'w') as cred:
			cred.write(f.encrypt(raw_data.encode()).decode())
			cred.flush()
			os.fsync(cred.fileno())
	except:
		return


def decrypt_file_content(path_name, password):
	kdf = Scrypt(
		salt=sha3_256(password.encode()).digest(),
		length=32,
		n=2**20,
		r=8,
		p=1,
	)
	key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
	f = Fernet(key)
	try:
		with open(path_name, 'r') as cred:
			return f.decrypt(cred.read().encode()).decode()
	except:
		return None