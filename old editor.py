from tkinter import *
from tkinter import ttk, filedialog, messagebox
import os, sys, threading, time, json, socket
from cryptography.fernet import Fernet

# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client.connect(("192.168.1.247", 7777))




text_box_list = []
file_list = []

BLACK = "#000000"
WHITE = "#ffffff"
SETTINGS_FILE = "editorSettings.json"
DEFAULT_SETTINGS = {"autosave":True, "darkmode":False, "encryptAll":False ,"last_opened_files": [] ,"encryptedfiles":{}, "passwordfiles":{}}


def add_tab(parent, contents, name):
    text = Text(undo=True)
    text_box_list.append(text)
    text = text_box_list[len(text_box_list) - 1]
    
    parent.add(text, text=name)
    text.insert('end', contents)
    text.configure(bg=BLACK if settings["darkmode"] == True else WHITE, 
                    fg=WHITE if settings["darkmode"] == True else BLACK,
                    insertbackground=WHITE if settings["darkmode"] == True else BLACK)

def openFile(*args):

    files = filedialog.askopenfilenames(title="Choose files")
    if not files:
        return
    

    for file in files:

        if file in file_list:
            continue
        if file in settings["encryptedfiles"].keys():
            
            contents = decryptFile(file, settings["encryptedfiles"][file])
            add_tab(notebook, contents, os.path.basename(file))    
            file_list.append(file)
        elif file in settings["passwordfiles"].keys(): 
            getPassword(file)
        else:
            with open(file, "r") as f:
                contents = f.read()
            add_tab(notebook, contents, os.path.basename(file))    
            file_list.append(file)

        



def delete_text(*args):
    text_box_list[notebook.index("current")].delete(1.0, END)

def newFile(*args):
    def inner(*args):
        t = text.get(1.0, END).strip()
        if not t.endswith(".txt"):
            t += ".txt"
        file_list.append(t)
        add_tab(notebook, "", t)
        window2.destroy()
    window2 = Toplevel()
    window2.config(bg=BLACK if settings["darkmode"] else WHITE)
    window2.geometry("250x50")  
    window2.resizable(False, False)
    window2.bind("<Return>", inner)
    Label(window2, text="Choose a file name", bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK).grid(row=1, column=1)
    text = Text(window2, height=1, width=15, bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK, insertbackground=WHITE if settings["darkmode"] else BLACK)
    text.grid(row=1, column=2, columnspan=2)
    Button(window2, text="Create", command=inner, bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK).grid(row=2, column=1, columnspan=3)
    
def debug(*args):
    print("called")

def deleteCurrentFile(*args):

    current = notebook.index("current")
    file = file_list[current]
    if os.path.exists(file):
        file_list.pop(current)
        text_box_list.pop(current)
        notebook.forget(current)
        os.remove(file)
    else:
        return

def changeFileName(*args):
    def inner(*args):
        file = file_list[index]
        t = text.get(1.0, END).strip()
        if not t.endswith(".txt"):
            t += ".txt"
        os.rename(file_list[index], t)
        f = os.path.basename(file)
        i = file_list.index(file)
        newname = file.replace(f, t)
        file_list[i] = newname
        notebook.tab(index, text=os.path.basename(newname))
        window2.destroy()
    index = notebook.index("current")
    window2 = Toplevel()
    window2.config(bg=BLACK if settings["darkmode"] else WHITE)
    window2.geometry("250x50")  
    window2.resizable(False, False)
    window2.bind("<Return>", inner)
    Label(window2, text="Choose a file name", bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK).grid(row=1, column=1)
    text = Text(window2, height=1, width=15, bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK, insertbackground=WHITE if settings["darkmode"] else BLACK)
    text.grid(row=1, column=2, columnspan=2)
    Button(window2, text="Rename", command=inner, bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK).grid(row=2, column=1, columnspan=3)


def Settings():
    global darkbutton
    settingswindow = Toplevel()
    settingswindow.title("Settings")
    settingswindow.geometry("200x200")
    Button(settingswindow, text="Autosave", command=lambda: getSettings("autosave")).pack()
    darkbutton = Button(settingswindow, text="Darkmode", command=lambda: getSettings("darkmode"))
    darkbutton.pack()

def setDarkmode(state):
    match state:
        case True:
            window.config(bg=BLACK)
            style.theme_use("Dark")
            menubar.configure(background=BLACK, foreground=WHITE)
            for textbox in text_box_list:
                textbox.configure(bg=BLACK, fg=WHITE, insertbackground=WHITE)
            darkbutton.config(bg="#11a607")
        case False:
            window.config(bg=WHITE)
            style.theme_use("Light")
            menubar.configure(background=WHITE, foreground=BLACK)
            for textbox in text_box_list:
                textbox.configure(bg=WHITE, fg=BLACK, insertbackground=BLACK)
            darkbutton.config(bg="white")
    window.update_idletasks()
    window.update()

def closeFile():
    i = notebook.index("current")
    file_list.pop(i)
    text_box_list.pop(i)
    notebook.forget(i)



def setAutosaveSetting():
    if settings["autosave"] == True:
        settings["autosave"] = False
    else:
        settings["autosave"] = True

def setDarkmodeSetting():
    if settings["darkmode"] == True:
        settings["darkmode"] = False
        setDarkmode(False)
    else:
        settings["darkmode"] = True
        setDarkmode(True)

def getSettings(setting):
    print(setting)
    match setting:
        case "autosave":
            setAutosaveSetting()
        case "darkmode":
            setDarkmodeSetting()

def saveFile(*args):

    index = notebook.index("current")
    file = file_list[index]
    text = text_box_list[index]
    
    print(settings)

    if file not in settings["encryptedfiles"].keys() and file not in settings["passwordfiles"].keys():
        with open(file, "w") as f:
            f.write(text.get(1.0, END))
    elif file in settings["passwordfiles"].keys():
        saveEncrypted(file, settings["passwordfiles"][file][1])
    else:
        fernet = Fernet(settings["encryptedfiles"][file])
        encrypted = fernet.encrypt(text.get(1.0, END).encode())
        with open(file, "w") as f:
            f.write(encrypted.decode())    

def saveAllFiles(*args):

    for i in range(len(file_list)):
        if file_list[i] not in settings["encryptedfiles"].keys() and file_list[i] not in settings["passwordfiles"].keys():
            with open(file_list[i], "w") as f:
                f.write(text_box_list[i].get(1.0, END))
        elif file_list[i] in settings["passwordfiles"].keys():
            saveEncrypted(file_list[i], settings["passwordfiles"][file_list[i]][1])
        else:
            fernet = Fernet(settings["encryptedfiles"][file_list[i]])
            encrypted = fernet.encrypt(text_box_list[i].get(1.0, END).encode())
            with open(file_list[i], "w") as f:
                f.write(encrypted.decode())    
 
def leave(*args):
    writeSettings()
    sys.exit(0)
    


def info():

    infowindow = Toplevel()
    Label(infowindow, text="Made by TheBusinessDude").pack()
    
# i need to learn sql 
def onstart():
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "w") as f:
            f.write(json.dumps(DEFAULT_SETTINGS, indent=2))
        return DEFAULT_SETTINGS
    with open(SETTINGS_FILE, "r") as f:
        return json.loads(f.read())


def checkSettings(settings):
    # setDarkmode(settings)
    if not settings["last_opened_files"]:
        return
    for file in settings["last_opened_files"]:
        
        if file in settings["encryptedfiles"].keys():
            contents = decryptFile(file, settings["encryptedfiles"][file])
            add_tab(notebook, contents, os.path.basename(file))    
            file_list.append(file)
        elif file in settings["passwordfiles"].keys(): 
            getPassword(file)
        else:
            with open(file, "r") as f:
                contents = f.read()
            add_tab(notebook, contents, os.path.basename(file))    
            file_list.append(file)
        


def closeAllFiles():

    
    for _ in range(len(text_box_list)):
        file_list.pop(0)
        text_box_list.pop(0)
        notebook.forget(0)

def writeSettings():

    settings["last_opened_files"] = file_list
    with open(SETTINGS_FILE, "w") as f:
        f.write(json.dumps(settings, indent=2))

def error(message):
    messagebox.showerror("Error", message)

def encryptFile(*args):
    try:
        file = file_list[notebook.index("current")]
        box = text_box_list[notebook.index("current")]
    except:
        error("No file selected, please try again")
        return


    if file not in settings["encryptedfiles"]:
        contents = box.get(1.0, END).encode()
        key = Fernet.generate_key()
        fernet = Fernet(key)
        contents = fernet.encrypt(contents)
        with open(file, "w") as f:
            f.write(contents.decode())

        settings["encryptedfiles"][file] = key.decode()

    else:
        error("File Is Already Encrypted")

def decryptFile(file, key):

    with open(file, "r") as f:
        message = f.read()
    
    fernet = Fernet(key)
    message = message.encode()
    message = fernet.decrypt(message)
    return message


def clearRecent():
    
    settings["last_opened_files"] = []


def passwordProtect(*args):
    def inner():
        password = text.get()
        password = password.strip()
        i = notebook.index("current")
        file = file_list[i]
        settings["passwordfiles"][file] = encryptPassword(password.encode(), file)
        window2.destroy()
    window2 = Toplevel()
    window2.config(bg=BLACK if settings["darkmode"] else WHITE)
    window2.geometry("150x75")  
    window2.resizable(False, False)
    window2.bind("<Return>", inner)
    Label(window2, text="Choose a password", bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK).grid(row=1, column=1)
    text = Entry(window2, show="*" , width=15, bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK, insertbackground=WHITE if settings["darkmode"] else BLACK)
    text.grid(row=2, column=1)
    Button(window2, text="choose", command=inner, bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK).grid(row=3, column=1, columnspan=3)

def encryptPassword(password, file):
    key = Fernet.generate_key()
    fernet = Fernet(key)
    password = fernet.encrypt(password)
    encryptPasswordFile(file, key)
    return [password.decode(), key.decode()]


def getPassword(file):
    def inner():
        password = text.get()
        password = password.strip()
        message = decryptPassword(settings["passwordfiles"][file][0], settings["passwordfiles"][file][1]).decode()
        print(password + " : " + message)
        if password == message:
            with open(file, "r") as f:
                contents = f.read()
            contents = decryptPassword(contents, settings["passwordfiles"][file][1])
            add_tab(notebook, contents, os.path.basename(file))    
            file_list.append(file)
            window2.destroy()
        else:
            print("uhhhh")
    window2 = Toplevel()
    window2.config(bg=BLACK if settings["darkmode"] else WHITE)
    window2.geometry("220x75")  
    window2.resizable(False, False)
    window2.bind("<Return>", inner)
    Label(window2, text="Enter the password for this document", bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK).grid(row=1, column=1)
    text = Entry(window2, show="*", width=15, bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK, insertbackground=WHITE if settings["darkmode"] else BLACK)
    text.grid(row=2, column=1)
    Button(window2, text="check", command=inner, bg=BLACK if settings["darkmode"] else WHITE, fg=WHITE if settings["darkmode"] else BLACK).grid(row=3, column=1, columnspan=2)

def decryptPassword(password, key):
    fernet = Fernet(key)
    password = password.encode()
    message = fernet.decrypt(password)
    return message

def encryptPasswordFile(file, key):
    fernet = Fernet(key)
    contents = open(file, "r").read()
    contents = contents.encode()
    encrypted = fernet.encrypt(contents).decode()
    with open(file, "w") as f:
        f.write(encrypted)

def saveEncrypted(file, key):
    fernet = Fernet(key)
    contents = text_box_list[notebook.index("current")].get(1.0, END)
    contents = contents.encode()
    encrypted = fernet.encrypt(contents).decode()
    with open(file, "w") as f:
        f.write(encrypted)


def switchtabs(*args):
    notebook.select((notebook.index("current") + 1) % 3)

def switchprevioustab(*args):
    notebook.select((notebook.index("current") - 1) % 3)







settings = onstart()



window = Tk()
window.title("Editor")
window.geometry("400x400")

notebook = ttk.Notebook(window)                                                                             
notebook.pack(expand=True, fill='both')

style = ttk.Style()
style.theme_create( "Dark", parent="alt", settings={
        "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0] }, "background": BLACK, "foreground": WHITE  },
        "TNotebook.Tab": {
            "configure": {"padding": [5, 1], "background": BLACK, "foreground": WHITE },
            "map":       {"background": [("selected", BLACK)],
                          "expand": [("selected", [1, 1, 1, 0])] } } } )

style.theme_create( "Light", parent="alt", settings={
        "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0] }, "background": WHITE, "foreground": BLACK },
        "TNotebook.Tab": {
            "configure": {"padding": [5, 1], "background": WHITE, "foreground": BLACK },
            "map":       {"background": [("selected", WHITE)],
                          "expand": [("selected", [1, 1, 1, 0])] } } } )


menubar = Menu(window)
window.config(menu=menubar)

checkSettings(settings)

window.bind("<Escape>", leave)
window.bind("<Control-n>", newFile)
window.bind("<Control-o>", openFile)
window.bind("<Control-s>", saveFile)
window.bind("<Control-Shift-S>", saveAllFiles)
window.bind("<Control-d>", deleteCurrentFile)
window.bind("<Control-r>", changeFileName)
window.bind("<Control-p>", passwordProtect)
window.bind("<Control-Tab>", switchtabs)
window.bind("<Control-Shift-Tab>", switchprevioustab)

filemenu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="File", menu=filemenu)
filemenu.add_command(label="New", command=newFile)
filemenu.add_command(label= "Open", command=openFile)
filemenu.add_command(label= "Save", command=saveFile)
filemenu.add_command(label= "Save All", command=saveAllFiles)
filemenu.add_command(label= "Delete Current File", command=deleteCurrentFile)
filemenu.add_command(label="Change file name", command=changeFileName)
filemenu.add_separator()
filemenu.add_command(label="Encrypt File Without Password", command=encryptFile)
filemenu.add_command(label="Password Protect", command=passwordProtect)
filemenu.add_command(label="Disable/Enable Autosave")
filemenu.add_separator()
filemenu.add_command(label="Clear recent files", command=clearRecent)
filemenu.add_command(label="Close File", command=closeFile)
filemenu.add_command(label="Close All Files", command=closeAllFiles)
filemenu.add_command(label= "Quit", command=leave)


editmenu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Edit")
editmenu.add_command(label="Copy")
editmenu.add_command(label="Paste")
editmenu.add_command(label="Cut")

textmenu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Text", menu=textmenu)
textmenu.add_command(label="Delete All Text", command=delete_text)

helpmenu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Help", menu=helpmenu)
helpmenu.add_command(label="Help")
helpmenu.add_command(label="Info", command=info)

setting = Menu(menubar, tearoff=0)
menubar.add_cascade(label="Settings", menu=setting)
setting.add_command(label="Settings", command=Settings)



window.mainloop()


writeSettings()