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


import re
import os

from enum import Enum
from sys import platform
from tkinter import Tk, Canvas, Frame, Label, Text, Entry, Button, Checkbutton, Menu, IntVar, Scrollbar, ttk, messagebox, filedialog, HORIZONTAL, NONE, DISABLED, END


class Action(Enum):
	OPEN = 1
	EXPORT = 2
	IMPORT = 3
	UPDATE = 4
	EXIT = 5


class ScrollableFrame(ttk.Frame):

	def __init__(self, container, *args, **kwargs):
		super().__init__(container, *args, **kwargs)

		self.container = container
		self.container.bind("<Configure>", self.__resize_frame__)

		self.canvas = Canvas(self)
		self.vertical_scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
		self.horizontal_scrollbar = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)

		self.scrollable_frame = ttk.Frame(self.canvas)
		self.scrollable_frame.bind("<Configure>", self.__resize_scrollbar__)

		self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
		self.canvas.configure(yscrollcommand=self.vertical_scrollbar.set)
		self.canvas.configure(xscrollcommand=self.horizontal_scrollbar.set)

		self.vertical_scrollbar.pack(side="right", fill="y")
		self.horizontal_scrollbar.pack(side="bottom", fill="x")

		if platform == 'linux' or platform == 'linux2':
			self.canvas.bind_all('<4>', self.__mousewheel__)
			self.canvas.bind_all('<5>', self.__mousewheel__)
		elif platform == 'win32' or platform == 'darwin':
			self.canvas.bind_all('<MouseWheel>', self.__mousewheel__)

		self.canvas.pack(side="left", fill="both", expand=True)

	def __resize_frame__(self, event):
		self.configure(width=self.container.winfo_width(), height=self.container.winfo_height())

	def __resize_scrollbar__(self, event):
		self.canvas.configure(scrollregion=self.canvas.bbox("all"))

	def __mousewheel__(self, event):
		if platform == 'linux' or platform == 'linux2':
			self.canvas.yview_scroll(-1 if event.num == 4 else 1, 'units')
		elif platform == 'win32':
			self.canvas.yview_scroll(-1 * (event.delta // 120), 'units')
		elif platform == 'darwin':
			pass


class MainUI:

	def __init__(self, master):
		self.action = None

		self.master = master

		self.frame = Frame(self.master, padx=2, pady=2)
		self.frame.pack()

		self.new_file_button = Button(self.frame, text="Open File", command=self.__open_button__)
		self.new_file_button.grid(row=0, padx=2, pady=2, column=0)

		self.export_file_button = Button(self.frame, text="Export Backup File", command=self.__export_button__)
		self.export_file_button.grid(row=1, padx=2, pady=2, column=0)

		self.import_file_button = Button(self.frame, text="Import Old Backup", command=self.__import_button__)
		self.import_file_button.grid(row=2, padx=2, pady=2, column=0)

		self.update_password_button = Button(self.frame, text="Change Password", command=self.__update_button__)
		self.update_password_button.grid(row=3, padx=2, pady=2, column=0)

		self.exit_button = Button(self.frame, text="Exit", command=self.__exit_button__)
		self.exit_button.grid(row=4, padx=2, pady=2, column=0)

		self.frame.update()

	def __open_button__(self):
		self.action = Action.OPEN
		self.master.destroy()

	def __export_button__(self):
		self.action = Action.EXPORT
		self.master.destroy()

	def __import_button__(self):
		self.action = Action.IMPORT
		self.master.destroy()

	def __update_button__(self):
		self.action = Action.UPDATE
		self.master.destroy()

	def __exit_button__(self):
		self.action = Action.EXIT
		self.master.destroy()


class PasswordUI:

	def __init__(self, master, generation):
		self.password = None

		self.master = master
		self.generation = generation
		self.pattern = re.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,}$")

		self.frame = Frame(self.master, padx=2, pady=2)
		self.frame.pack()

		self.insert_password_label = Label(self.frame, text="New Password:") if self.generation else Label(self.frame, text="Password:")
		self.insert_password_label.grid(row=0, padx=2, pady=2, column=0)

		self.insert_password_text = Entry(self.frame, show="*", width=40)
		self.insert_password_text.grid(row=0, padx=2, pady=2, column=1)
		self.insert_password_text.insert(END, '')
		self.insert_password_text.focus_set()

		self.insert_password_button = Button(self.frame, text="Submit", command=self.__submit_button__)
		self.insert_password_button.grid(row=1, padx=2, pady=2, column=0, columnspan=2)

		self.master.bind('<Return>', self.__submit_button__)

		self.frame.update()

	def __submit_button__(self, e=None):
		if self.generation and not re.search(self.pattern, self.insert_password_text.get().strip()):
			messagebox.showerror(
				title="Password Manager",
				message="The password must be at least 8 characters long and must include:\n\n"
						" - at least one lowercase character\n"
						" - at least one uppercase character\n"
						" - at least one number\n"
						" - at least one of: @$!%*#?&\n"
			)
		else:
			self.password = self.insert_password_text.get().strip()
			self.master.destroy()


class ShowDataUI:

	def __init__(self, master, data):
		self.master = master

		self.data = None

		self.frame = ScrollableFrame(self.master)
		self.frame.pack()

		self.service_label = Label(self.frame.scrollable_frame, width=40, text="SERVICE")
		self.service_label.grid(row=0, padx=2, pady=2, column=0)

		self.user_label = Label(self.frame.scrollable_frame, width=40, text="USERNAME")
		self.user_label.grid(row=0, padx=2, pady=2, column=1)

		self.password_label = Label(self.frame.scrollable_frame, width=40, text="PASSWORD")
		self.password_label.grid(row=0, padx=2, pady=2, column=2)

		self.search_entry = Entry(self.frame.scrollable_frame, width=20, justify='center', foreground='grey')
		self.search_entry.grid(row=0, padx=2, pady=2, column=3)
		self.search_entry.insert(END, '')
		self.search_entry.focus_set()

		self.search_entry.bind("<KeyRelease>", self.__search__)

		self.count = 0

		self.entries = {}

		if 'data' in data and 'service' in data['data']:

			for service in sorted(data['data']['service'].keys()):

				if any(isinstance(e, list) for e in data['data']['service'][service]):

					for user, password in data['data']['service'][service]:

						self.count += 1

						service_text = Entry(self.frame.scrollable_frame, width=40)
						service_text.grid(row=self.count, padx=2, pady=2, column=0)
						service_text.insert(END, service)
						service_text.configure(state='readonly', readonlybackground='white smoke')

						user_text = Entry(self.frame.scrollable_frame, width=40)
						user_text.grid(row=self.count, padx=2, pady=2, column=1)
						user_text.insert(END, user)
						user_text.configure(state='readonly', readonlybackground='white smoke')

						password_entry = Entry(self.frame.scrollable_frame, show='*', width=40)
						password_entry.grid(row=self.count, padx=2, pady=2, column=2)
						password_entry.insert(END, password)
						password_entry.configure(state='readonly', readonlybackground='white smoke')

						delete_checkbutton_var = IntVar()
						delete_checkbutton = Checkbutton(self.frame.scrollable_frame, variable=delete_checkbutton_var, command=self.__show_password__)
						delete_checkbutton.grid(row=self.count, padx=2, pady=2, column=3)

						self.entries['_'.join((service, user))] = (service_text, user_text, password_entry, delete_checkbutton_var, delete_checkbutton)

				else:

					self.count += 1

					service_text = Entry(self.frame.scrollable_frame, width=40)
					service_text.grid(row=self.count, padx=2, pady=2, column=0)
					service_text.insert(END, service)
					service_text.configure(state='readonly', readonlybackground='white smoke')

					user = data['data']['service'][service][0]

					user_text = Entry(self.frame.scrollable_frame, width=40)
					user_text.grid(row=self.count, padx=2, pady=2, column=1)
					user_text.insert(END, user)
					user_text.configure(state='readonly', readonlybackground='white smoke')

					password = data['data']['service'][service][1]

					password_entry = Entry(self.frame.scrollable_frame, show='*', width=40)
					password_entry.grid(row=self.count, padx=2, pady=2, column=2)
					password_entry.insert(END, password)
					password_entry.configure(state='readonly', readonlybackground='white smoke')

					delete_checkbutton_var = IntVar()
					delete_checkbutton = Checkbutton(self.frame.scrollable_frame, variable=delete_checkbutton_var, command=self.__show_password__)
					delete_checkbutton.grid(row=self.count, padx=2, pady=2, column=3)

					self.entries['_'.join((service, user))] = (service_text, user_text, password_entry, delete_checkbutton_var, delete_checkbutton)

		self.save_button = Button(self.frame.scrollable_frame, text="SAVE", command=self.__save_button__)
		self.save_button.grid(row=self.count+1, padx=2, pady=2, column=0)

		self.new_button = Button(self.frame.scrollable_frame, text="NEW", command=self.__new_button__)
		self.new_button.grid(row=self.count+1, padx=2, pady=2, column=1)

		self.cancel_button = Button(self.frame.scrollable_frame, text="CANCEL", command=self.__cancel_button__)
		self.cancel_button.grid(row=self.count+1, padx=2, pady=2, column=2)
		self.new_button.grid(row=self.count+1, padx=2, pady=2, column=1)

		self.delete_button = Button(self.frame.scrollable_frame, text="DELETE", command=self.__delete_button__)
		self.delete_button.grid(row=self.count+1, padx=2, pady=2, column=3)

		self.context_menu = Menu(self.master, tearoff=0)
		self.context_menu.add_command(label="Cut")
		self.context_menu.add_command(label="Copy")
		self.context_menu.add_command(label="Paste")
		if platform == 'linux' or platform == 'linux2':
			self.frame.scrollable_frame.bind_all('<3>', self.__do_popup__)
		elif platform == 'win32' or platform == 'darwin':
			self.frame.scrollable_frame.bind_all('<Button-3>', self.__do_popup__)

		self.frame.update()

	def __save_button__(self):
		tmp_data = { 'data': { 'service': { }, 'username': { } } }
		for service_user in self.entries:
			tmp_service = self.entries[service_user][0].get().strip()
			tmp_user = self.entries[service_user][1].get().strip()
			tmp_password = self.entries[service_user][2].get().strip()
			if tmp_service == '' and tmp_user == '' and tmp_password == '':
				continue
			elif tmp_service == '' or tmp_user == '' or tmp_password == '':
				messagebox.showerror(
					title="Password Manager",
					message="At least one entry has missing arguments"
				)
				tmp_data = None
				break
			elif tmp_service in tmp_data['data']['service'] and tmp_user in [user for user, _ in tmp_data['data']['service'][tmp_service]]:
				messagebox.showerror(
					title="Password Manager",
					message="Service {0} with User {1} already exists".format(tmp_service, tmp_user)
				)
				tmp_data = None
				break
			if not tmp_service in tmp_data['data']['service']:
				tmp_data['data']['service'][tmp_service] = []
			tmp_data['data']['service'][tmp_service].append([tmp_user, tmp_password])
			if not tmp_user in tmp_data['data']['username']:
				tmp_data['data']['username'][tmp_user] = []
			tmp_data['data']['username'][tmp_user].append([tmp_service, tmp_password])
		if tmp_data:
			self.data = tmp_data
			self.entries = None
			self.count = 0
			self.master.destroy()

	def __new_button__(self):
		self.count += 1

		self.save_button.grid(row=self.count+1, padx=2, pady=2, column=0)
		self.new_button.grid(row=self.count+1, padx=2, pady=2, column=1)
		self.cancel_button.grid(row=self.count+1, padx=2, pady=2, column=2)
		self.delete_button.grid(row=self.count+1, padx=2, pady=2, column=3)

		service_text = Entry(self.frame.scrollable_frame, width=40)
		service_text.grid(row=self.count, padx=2, pady=2, column=0)
		service_text.insert(END, '')

		user_text = Entry(self.frame.scrollable_frame, width=40)
		user_text.grid(row=self.count, padx=2, pady=2, column=1)
		user_text.insert(END, '')

		password_entry = Entry(self.frame.scrollable_frame, show='*', width=40)
		password_entry.grid(row=self.count, padx=2, pady=2, column=2)
		password_entry.insert(END, '')

		delete_checkbutton_var = IntVar()
		delete_checkbutton = Checkbutton(self.frame.scrollable_frame, variable=delete_checkbutton_var, command=self.__show_password__)
		delete_checkbutton.grid(row=self.count, padx=2, pady=2, column=3)

		self.frame.canvas.update_idletasks()
		self.frame.canvas.yview_moveto('1.0')

		self.entries[''.join(('__NEW_SVC_USR__', str(self.count)))] = (service_text, user_text, password_entry, delete_checkbutton_var, delete_checkbutton)

	def __cancel_button__(self):
		self.data = None
		self.entries = None
		self.count = 0
		self.master.destroy()

	def __delete_button__(self):
		for service_user in list(self.entries):
			if self.entries[service_user][3].get() == 1:
				for widget in self.entries[service_user]:
					if not isinstance(widget, IntVar):
						widget.grid_forget()
						widget.destroy()
				del self.entries[service_user]

	def __show_password__(self):
		for service_user in self.entries:
			if self.entries[service_user][3].get() == 1:
				self.entries[service_user][2].configure(show='')
			else:
				self.entries[service_user][2].configure(show='*')

	def __do_popup__(self, event):
		try:
			self.context_menu.entryconfigure("Cut", command=lambda: event.widget.event_generate("<<Cut>>"))
			self.context_menu.entryconfigure("Copy", command=lambda: event.widget.event_generate("<<Copy>>"))
			self.context_menu.entryconfigure("Paste", command=lambda: event.widget.event_generate("<<Paste>>"))
			self.context_menu.tk_popup(event.x_root, event.y_root)
		finally:
			self.context_menu.grab_release()

	def __search__(self, e=None):
		keyword = self.search_entry.get().strip().lower()
		for service_user in self.entries:
			tmp_service = self.entries[service_user][0].get().strip()
			tmp_user = self.entries[service_user][1].get().strip()
			if keyword == '' or keyword in tmp_service.lower() or keyword in tmp_user.lower():
				self.entries[service_user][0].grid()
				self.entries[service_user][1].grid()
				self.entries[service_user][2].grid()
				self.entries[service_user][4].grid()
			else:
				self.entries[service_user][0].grid_remove()
				self.entries[service_user][1].grid_remove()
				self.entries[service_user][2].grid_remove()
				self.entries[service_user][4].grid_remove()


class ExportBackupUI:

	def __init__(self, master):
		self.directory = None

		self.master = master

		self.frame = Frame(self.master, padx=2, pady=2)
		self.frame.pack()

		self.select_dir_label = Label(self.frame, text="Backup directory:")
		self.select_dir_label.grid(row=0, padx=2, pady=2, column=0)

		self.select_dir_text = Text(self.frame, wrap=NONE, width=40, height=1)
		self.select_dir_text.grid(row=0, padx=2, pady=2, column=1)
		self.select_dir_text.insert(END, '')

		self.select_dir_button = Button(self.frame, text="Browse", command=self.__browse_button__)
		self.select_dir_button.grid(row=0, padx=2, pady=2, column=2)

		self.select_dir_text_scroll = Scrollbar(self.frame, orient=HORIZONTAL, command=self.select_dir_text.xview)
		self.select_dir_text_scroll.grid(row=1, padx=2, pady=2, column=1, sticky='NSEW')
		self.select_dir_text['xscrollcommand'] = self.select_dir_text_scroll.set

		self.submit_dir_button = Button(self.frame, text="Submit", command=self.__submit_button__)
		self.submit_dir_button.grid(row=2, padx=2, pady=2, column=0, columnspan=3)

		self.frame.update()

	def __browse_button__(self):
		self.select_dir_text.delete('1.0', END)
		self.select_dir_text.insert(END, filedialog.askdirectory())

	def __submit_button__(self):
		if self.select_dir_text.get('1.0', END).strip() == '':
			messagebox.showerror(title="Error", message="The directory's field cannot be empty")
		elif not os.path.exists(self.select_dir_text.get('1.0', END).strip()):
			messagebox.showerror(title="Error", message="The specified directory does not exist")
		elif not os.path.isdir(self.select_dir_text.get('1.0', END).strip()):
			messagebox.showerror(title="Error", message="The specified path is not a directory")
		else:
			self.directory = self.select_dir_text.get('1.0', END).strip()
			self.master.destroy()


class ImportBackupUI:

	def __init__(self, master):
		self.file = None

		self.master = master

		self.frame = Frame(self.master, padx=2, pady=2)
		self.frame.pack()

		self.select_file_label = Label(self.frame, text="Backup file:")
		self.select_file_label.grid(row=0, padx=2, pady=2, column=0)

		self.select_file_text = Text(self.frame, wrap=NONE, width=40, height=1)
		self.select_file_text.grid(row=0, padx=2, pady=2, column=1)
		self.select_file_text.insert(END, '')

		self.select_file_button = Button(self.frame, text="Browse", command=self.__browse_button__)
		self.select_file_button.grid(row=0, padx=2, pady=2, column=2)

		self.select_file_text_scroll = Scrollbar(self.frame, orient=HORIZONTAL, command=self.select_file_text.xview)
		self.select_file_text_scroll.grid(row=1, padx=2, pady=2, column=1, sticky='NSEW')
		self.select_file_text['xscrollcommand'] = self.select_file_text_scroll.set

		self.submit_file_button = Button(self.frame, text="Submit", command=self.__submit_button__)
		self.submit_file_button.grid(row=2, padx=2, pady=2, column=0, columnspan=3)

		self.frame.update()

	def __browse_button__(self):
		self.select_file_text.delete('1.0', END)
		self.select_file_text.insert(END, filedialog.askopenfilename(filetypes=(('Bakup files', '*.bak'), ('All files', '*.*'))))

	def __submit_button__(self):
		if self.select_file_text.get('1.0', END).strip() == '':
			messagebox.showerror(title="Error", message="The file's field cannot be empty")
		elif not os.path.exists(self.select_file_text.get('1.0', END).strip()):
			messagebox.showerror(title="Error", message="The specified file does not exist")
		elif not os.path.isfile(self.select_file_text.get('1.0', END).strip()):
			messagebox.showerror(title="Error", message="The specified path is not a file")
		else:
			self.file = self.select_file_text.get('1.0', END).strip()
			self.master.destroy()


class AnimateProgressUI:

	def __init__(self, master, message, running):
		self.master = master
		self.message = message
		self.running = running

		self.frame = ttk.Frame(self.master)
		self.frame.pack()

		self.message_label = ttk.Label(self.frame, text=self.message)
		self.message_label.grid(row=0, padx=2, pady=2, column=0)

		self.message_label.update()

		self.progress_bar = ttk.Progressbar(self.frame, orient=HORIZONTAL, length=self.message_label.winfo_width(), mode='indeterminate')
		self.progress_bar.grid(row=1, padx=2, pady=2, column=0)

		self.frame.update()

		self.progress_bar.start(25)

		self.master.after(250, self.__check_running__)

	def __check_running__(self):
		if self.running.is_set():
			self.master.destroy()
		else:
			self.master.after(250, self.__check_running__)


def show_info_message(message):
	root = Tk()
	root.withdraw()
	messagebox.showinfo(title="Password Manager", message="{0}".format(message))
	root.destroy()


def show_error_message(message):
	root = Tk()
	root.withdraw()
	messagebox.showerror(title="Password Manager", message="{0}".format(message))
	root.destroy()


def show_request_message(message):
	root = Tk()
	root.withdraw()
	response = messagebox.askyesno(title="Password Manager", message="{0}".format(message))
	root.destroy()
	return response


def choose_action():
	root = Tk()
	root.title("Password Manager")
	main_ui = MainUI(master=root)
	w = (root.winfo_width() * 150) // 100
	h = root.winfo_height()
	x = (root.winfo_screenwidth() // 2) - (w // 2)
	y = (root.winfo_screenheight() // 2) - (h // 2)
	root.geometry('{0}x{1}+{2}+{3}'.format(w, h, x, y))
	root.lift()
	root.mainloop()
	if main_ui:
		return main_ui.action


def insert_password(generation=False):
	root = Tk()
	root.title("Password Manager")
	password_ui = PasswordUI(master=root, generation=generation)
	w = root.winfo_width()
	h = root.winfo_height()
	x = (root.winfo_screenwidth() // 2) - (w // 2)
	y = (root.winfo_screenheight() // 2) - (h // 2)
	root.geometry('{0}x{1}+{2}+{3}'.format(w, h, x, y))
	root.lift()
	root.mainloop()
	if password_ui:
		return password_ui.password


def show_data(data):
	root = Tk()
	root.title("Password Manager")
	show_data_ui = ShowDataUI(master=root, data=data)
	w = (root.winfo_screenwidth() * 70) // 100
	h = (root.winfo_screenheight() * 85) // 100
	x = (root.winfo_screenwidth() // 2) - (w // 2)
	y = (root.winfo_screenheight() // 2) - (h // 2)
	root.geometry('{0}x{1}+{2}+{3}'.format(w, h, x, y))
	root.lift()
	root.mainloop()
	if show_data_ui:
		return show_data_ui.data


def export_backup():
	root = Tk()
	root.title("Password Manager")
	export_backup_ui = ExportBackupUI(master=root)
	w = root.winfo_width()
	h = root.winfo_height()
	x = (root.winfo_screenwidth() // 2) - (w // 2)
	y = (root.winfo_screenheight() // 2) - (h // 2)
	root.geometry('{0}x{1}+{2}+{3}'.format(w, h, x, y))
	root.lift()
	root.mainloop()
	if export_backup_ui:
		return export_backup_ui.directory


def import_backup():
	root = Tk()
	root.title("Password Manager")
	import_backup_ui = ImportBackupUI(master=root)
	w = root.winfo_width()
	h = root.winfo_height()
	x = (root.winfo_screenwidth() // 2) - (w // 2)
	y = (root.winfo_screenheight() // 2) - (h // 2)
	root.geometry('{0}x{1}+{2}+{3}'.format(w, h, x, y))
	root.lift()
	root.mainloop()
	if import_backup_ui:
		return import_backup_ui.file


def show_progress_background_work(message, running):
	root = Tk()
	root.title("Password Manager")
	animate_progress_ui = AnimateProgressUI(master=root, message=message, running=running)
	w = root.winfo_width()
	h = root.winfo_height()
	x = (root.winfo_screenwidth() // 2) - (w // 2)
	y = (root.winfo_screenheight() // 2) - (h // 2)
	root.geometry('{0}x{1}+{2}+{3}'.format(w, h, x, y))
	root.lift()
	root.mainloop()