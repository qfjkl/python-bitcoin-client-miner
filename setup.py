import sys
from cx_Freeze import setup, Executable
from cx_Freeze.dist import build_exe

path = ['Conf-Files/']
build_exe_options =  {"packages": ['os', 'socket', 'threading', 'json', 'time', 'hashlib', 'codecs', 'struct', 'pickle', 'platform', 'tqdm', 'requests', 'winreg'],
                        "excludes": ['tkinter'],
                        "include_files": path
                    }

setup(
    name = "MSN-CLIENT(1)",
    version = "0.1",
    description= "Application de minage",
    options = {"build_exe": build_exe_options},
    executables= [Executable("MSN-CLIENT.py", icon='Conf-Files/MSN.ico', copyright="Copyright (C) 2021 MSN")] 
)