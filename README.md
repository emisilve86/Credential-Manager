# Credential Manager #

### A tool to keep your Credentials Safe ###

------

## Brief ##

This is a Python program graphically based on the `Tkinter` UI, which aims to provide users with a tool that keeps all their credentials securely stored locally. It allows to encrypt data using a strong, completely random key that is extremely difficult to figure out unless you know the relative, easy to remember master passord. It allows to export backups possibly encrypted with different passwords, and to restore old backups in case of data loss or corruption. In addition, the master password can be easily updated whenever it is considered no longer safe.

## Security ##

The reason why data is kept safe is due to the cryptography protocol implemented by the `Fernet` class from the `Cryptography` package, which guarantees that a message encrypted using it cannot be manipulated or read without the key. Fernet is an implementation of symmetric authenticated cryptography built on top of a number of standard cryptographic primitives. Specifically it uses [`AES`](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in [`CBC`](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) mode with a 128-bit key for encryption, using [`PKCS7`](https://en.wikipedia.org/wiki/PKCS) padding and [`HMAC`](https://en.wikipedia.org/wiki/HMAC) with [`SHA256`](https://it.wikipedia.org/wiki/Secure_Hash_Algorithm) for authentication. More details are given at this [url](https://github.com/fernet/spec/blob/master/Spec.md).

Moreover, the derivation of the key is made computationally intensive by relaying on the [`Scrypt`](https://en.wikipedia.org/wiki/Scrypt) algorithm specifically designed for password storage to be resistant against hardware-assisted attackers by having a tunable memory cost. In general, the memory cost of `Scrypt` is affected by the values of two parameters, `n` and `r`, while `n` also determines the number of iterations performed. A third parameter `p` increases the computational cost without affecting memory usage. Their values were chosen following the [`RFC7914`](https://datatracker.ietf.org/doc/html/rfc7914.html) recommendations for our specific purpose.

Additionally, when data is going to be encrypted, it is also inflated with leading and trailing random sequences of specific characters so as not to generate identical backups even when they hides same data that resides at a random position within a minimum size layout. This makes difficult to determine if the encrypted file maintains zero, one or more credentials stored inside.

## Features ##

First time the application is used, the encrypted file must be created and a master password is prompted to the user. Master password must have a minimum lenght and must fulfill a regular expression specifically devised to verify whether the user has inserted certain characters or not.

This application allows to keep track of an unlimited number of tuples that are made of a service, a username and a password. Same service may appear multiple times with different username values. No restrictions are put to username and password.

Password are not directly shown when accessing the window containing credentials but their characters are all substituted with the `*` one. To read a password, the relative checkbox must be selected to reveal its value.

The window is fully scrollable with the mouse wheel. To quickly find a service or a specific username, a SEARCH bar is made available to users at the top-right corner of the window.

New entries can be added by pushing the button NEW. Old ones can be deleted by pushing the button DELETE after having selected the relative checkbox. By the way, old entries cannot be directly modified since their content is protected against accidental changes.

A context menu window can be opened over any entry selected by the user by clicking the mouse's right button. It provides three functionalities that are CUT, COPY and PASTE. Alternatively, shorthands such as CTRL+C and CTRL+V are always available.

## Requirements ##

To run this program a Python3 interpreter is required together with the following packages that are unlikely to be installed already by default:

- `Tkinter`
- `json`
- `cryptography`

Others may be missing, which can be installed with a packege manager (*e.g.* `Pip`).

## Bundle ##

The `.spec` file placed into the root directory of this repository can be used with PyInstaller package to generate bundles for the common OSs. It is enough to run `> pyinstaller CManager.spec` to generate a bundle for the OS that is currently hosting the Python environment. PyInstaller bundles a Python application and all its dependencies into a single package, so that the user can run the application without installing a Python interpreter or any modules.