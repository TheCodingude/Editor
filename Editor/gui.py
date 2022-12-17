from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Notebook

import os, json
import settings

def leave(key):
    exit(0)


window = Tk()
window.geometry("400x400")

notebook = Notebook(window)
notebook.pack(expand=True, fill="both")


window.bind("<Escape>", leave)

window.mainloop()