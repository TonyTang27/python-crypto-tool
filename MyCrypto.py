import tkinter as tk
from tkinter import ttk

from base64 import b64decode,b64encode
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

#===============↓=== RSA Random ===↓===============#
def generate_RSA(bits=1024, ex=65537): 
    #Generate an RSA keypair with an exponent of 65537 in PEM format 
    #param: bits The key length in bits 
    #Return secret key and public key 
    
    #_RSA.generate_py(bits, rf, progress_func, e)
    new_key = RSA.generate(bits, e = ex)
    public_key = new_key.publickey().exportKey("PEM") 
    secret_key = new_key.exportKey("PEM")
    return secret_key, public_key, new_key.n, new_key.e, new_key.d, new_key.p, new_key.q, new_key.u

#===============↓=== RSA gen key button ===↓===============#
def gen_rsa_key_pair():
    #print (type(key_length.get()))
    sk, pk, n, e, d, p, q, u = generate_RSA(key_length.get(), key_ex.get())

    dp = hex(d % (p-1)).replace('0x',"").upper()
    dq = hex(d % (q-1)).replace('0x',"").upper()
    n = hex(n).replace('0x',"").upper()
    e = hex(e).replace('0x',"").upper()
    d = hex(d).replace('0x',"").upper()
    p = hex(p).replace('0x',"").upper()
    q = hex(q).replace('0x',"").upper()
    u = hex(u).replace('0x',"").upper()
    
    #clear old data
    Text_Pu_Base64.delete(0.0, tk.END)
    Text_Pi_Base64.delete(0.0, tk.END)
    Text_Pu_Hex.delete(0.0, tk.END)
    Text_Pi_Hex.delete(0.0, tk.END)
    
    n_Text.delete(0.0, tk.END)
    e_Text.delete(0.0, tk.END)
    d_Text.delete(0.0, tk.END)
    p_Text.delete(0.0, tk.END)
    q_Text.delete(0.0, tk.END)
    dp_Text.delete(0.0, tk.END)
    dq_Text.delete(0.0, tk.END)
    u_Text.delete(0.0, tk.END)
    
    #Show Base64 pem format
    Text_Pu_Base64.insert(tk.END, pk.decode("utf-8"))
    Text_Pi_Base64.insert(tk.END, sk.decode("utf-8"))
    
    #transfer Base64 to Hex
    h_pk = pk.replace(b'-----BEGIN PUBLIC KEY-----\n',b"")
    h_pk = h_pk.replace(b'\n-----END PUBLIC KEY-----',b"")
    
    Text_Pu_Hex.insert(tk.END, b64decode(h_pk).hex().upper())
    
    h_sk = sk.replace(b'-----BEGIN RSA PRIVATE KEY-----\n',b"")
    h_sk = h_sk.replace(b'\n-----END RSA PRIVATE KEY-----',b"")
    
    Text_Pi_Hex.insert(tk.END, b64decode(h_sk).hex().upper())
    
    #Show components
    n_Text.insert(tk.END, n)
    e_Text.insert(tk.END, e)
    d_Text.insert(tk.END, d)
    p_Text.insert(tk.END, p)
    q_Text.insert(tk.END, q)
    dp_Text.insert(tk.END, dp)
    dq_Text.insert(tk.END, dq)
    u_Text.insert(tk.END, u)
    
    #show length
    n_len_label.configure(text=len(n)//2)
    d_len_label.configure(text=len(d)//2)
    p_len_label.configure(text=len(p)//2)
    q_len_label.configure(text=len(q)//2)
    dp_len_label.configure(text=len(dp)//2)
    dq_len_label.configure(text=len(dq)//2)
    u_len_label.configure(text=len(u)//2)
    
    
def Import_pu():
    
    p = int(p_Text.get(1.0,tk.END).replace('\n',""), 16)
    q = int(q_Text.get(1.0,tk.END).replace('\n',""), 16)
    dp = int(dp_Text.get(1.0,tk.END).replace('\n',""), 16)
    dq = int(dq_Text.get(1.0,tk.END).replace('\n',""), 16)
    u = int(u_Text.get(1.0,tk.END).replace('\n',""), 16)
    
    n = p * q
    print (n)
    
    lcm = (p - 1).lcm(q - 1)
    print (lcm)
    #d = e.inverse(lcm)
    
    '''
    Text_Pu_Base64.delete(0.0, tk.END)
    Text_Pu_Hex.delete(0.0, tk.END)
    length_input.delete(0,tk.END)
    ex_input.delete(0,tk.END)
    
    key_length = len(n_Text.get(1.0,tk.END).replace('\n',"")) * 4
    
    n = int(n_Text.get(1.0,tk.END).replace('\n',""), 16)
    e = int(e_Text.get(1.0,tk.END).replace('\n',""), 16)
    
    new_key = RSA.construct((n, e))
    public_key = new_key.publickey().exportKey("PEM")

    pu = public_key.replace(b'-----BEGIN PUBLIC KEY-----\n',b"")
    pu = pu.replace(b'\n-----END PUBLIC KEY-----',b"")
    #print (pu)
    
    Text_Pu_Base64.insert(tk.END, public_key.decode("utf-8"))
    Text_Pu_Hex.insert(tk.END, b64decode(pu).hex().upper())
    length_input.insert(0, str(key_length))
    ex_input.insert(0, str(e))

    #show length
    n_len_label.configure(text=len(n_Text.get(1.0,tk.END).replace('\n',""))//2)
'''

def import_both():
    Text_Pu_Base64.delete(0.0, tk.END)
    Text_Pi_Base64.delete(0.0, tk.END)
    Text_Pu_Hex.delete(0.0, tk.END)
    Text_Pi_Hex.delete(0.0, tk.END)
    length_input.delete(0,tk.END)
    ex_input.delete(0,tk.END)
    
    p_Text.delete(0.0, tk.END)
    q_Text.delete(0.0, tk.END)
    dp_Text.delete(0.0, tk.END)
    dq_Text.delete(0.0, tk.END)
    u_Text.delete(0.0, tk.END)
    
    key_length = len(n_Text.get(1.0,tk.END).replace('\n',"")) * 4
    
    n = int(n_Text.get(1.0,tk.END).replace('\n',""), 16)
    e = int(e_Text.get(1.0,tk.END).replace('\n',""), 16)
    d = int(d_Text.get(1.0,tk.END).replace('\n',""), 16)
    
    new_key = RSA.construct((n, e, d))
    public_key = new_key.publickey().exportKey("PEM")
    secret_key = new_key.exportKey("PEM")

    pu = public_key.replace(b'-----BEGIN PUBLIC KEY-----\n',b"")
    pu = pu.replace(b'\n-----END PUBLIC KEY-----',b"")
    #print (pu)
    
    Text_Pu_Base64.insert(tk.END, public_key.decode("utf-8"))
    Text_Pu_Hex.insert(tk.END, b64decode(pu).hex().upper())

    pi = secret_key.replace(b'-----BEGIN RSA PRIVATE KEY-----\n',b"")
    pi = pi.replace(b'\n-----END RSA PRIVATE KEY-----',b"")
    #print (pi)

    dp = hex(d % (new_key.p-1)).replace('0x',"").upper()
    dq = hex(d % (new_key.q-1)).replace('0x',"").upper()    
    p = hex(new_key.p).replace('0x',"").upper()
    q = hex(new_key.q).replace('0x',"").upper()
    u = hex(new_key.u).replace('0x',"").upper()
    
    #Show components
    p_Text.insert(tk.END, p)
    q_Text.insert(tk.END, q)
    dp_Text.insert(tk.END, dp)
    dq_Text.insert(tk.END, dq)
    u_Text.insert(tk.END, u)
    
    Text_Pi_Base64.insert(tk.END, secret_key.decode("utf-8"))
    Text_Pi_Hex.insert(tk.END, b64decode(pi).hex().upper())   
    length_input.insert(0, str(key_length))
    ex_input.insert(0, str(e))    

    #show length
    n_len_label.configure(text=len(n_Text.get(1.0,tk.END).replace('\n',""))//2)
    d_len_label.configure(text=len(d_Text.get(1.0,tk.END).replace('\n',""))//2)

#===============↓=== Public key encrytion button ===↓===============#
def public_encryption():
    En_B64_Text.delete(0.0, tk.END)
    En_Hex_Text.delete(0.0, tk.END)
    
    text_in = De_Hex_Text.get(1.0,tk.END)
    text_in = text_in.replace('\n',"")
    
    msg = bytes.fromhex(text_in)
    #print (Text_Pu_Base64.get(1.0,tk.END), '\n')
    
    keyPub = RSA.importKey(Text_Pu_Base64.get(1.0,tk.END))
    cipher = Cipher_PKCS1_v1_5.new(keyPub)
    cipher_text = cipher.encrypt(msg)
    emsg = b64encode(cipher_text)
    
    En_B64_Text.insert(tk.END, emsg.decode("utf-8"))
    En_Hex_Text.insert(tk.END, cipher_text.hex().upper())
    
#===============↓=== Private key decrytion button ===↓===============#
def Private_decryption(): 
    text_in = En_Hex_Text.get(1.0,tk.END)
    text_in = text_in.replace('\n',"")
    
    msg = bytes.fromhex(text_in)
    random_generator = Random.new().read
    rsakey = RSA.importKey(Text_Pi_Base64.get(1.0,tk.END))
    plain = Cipher_PKCS1_v1_5.new(rsakey)
    result = plain.decrypt(msg, random_generator)
    print (result)
    emsg = b64encode(result)
    print (emsg)
    
    De_B64_Text.insert(tk.END, emsg.decode("utf-8"))
    De_Hex_Text.insert(tk.END, result.hex().upper())
    #print (result.hex())

#===============↓=== Base64 to Hex event ===↓===============#   
#input str; output str
def Base64_to_Hex(data, outF):
    data = data.replace('\n',"")
    #print (bytes.fromhex(data))
    if data != "\n":
        outF.delete(0.0, tk.END)
        outF.insert(tk.END, b64decode(data).hex().upper())
        
#===============↓=== Hex to Base64 event ===↓===============#
#input str; output str
def Hex_to_Base64(data, outF):
    data = bytes.fromhex(data.replace('\n',""))
    if data != "\n":
        outF.delete(0.0, tk.END)
        outF.insert(tk.END, b64encode(data))
        
#===(1)============↓=== Main_Windows start ===↓============(1)===#
Main_Windows = tk.Tk()
Main_Windows.resizable(0, 0)
Main_Windows.title('Crypto Tool')
#Windows' size
#tkTop.geometry('1200x800')
#===(2)============↓=== Main_frame start ===↓============(2)===#
Main_frame = tk.Frame(Main_Windows ,bg='blue')

#===(3)============↓=== Main_Book start ===↓============(3)===#
Main_Book = ttk.Notebook(Main_frame, padding = 10)

#RSA_tab
RSA_tab = ttk.Frame(Main_Book)
#DES_tab
DES_tab = ttk.Frame(Main_Book)

#===(4)============↓=== RSA_book start ===↓============(4)===#
RSA_book = ttk.Notebook(RSA_tab, padding = 10)

#Gen_Key
#Gen_Key_tab = ttk.Frame(RSA_book)
#Used_KeyPair
Used_KeyPair_tab = ttk.Frame(RSA_book)
#Public key encryption
Encry_Decry_tab = ttk.Frame(RSA_book)

'''
#===(4.1)============↓=== Gen_Key_tab start ===↓============(4.1)===#

#===(4.1.1)============↓=== Pu_frame start ===↓============(4.1.1)===#
Pu_frame = ttk.Frame(Gen_Key_tab, padding = 10)

Pu_scrollbar = tk.Scrollbar(Pu_frame)
Pu_scrollbar.pack(side=tk.RIGHT,fill=tk.Y)

Text_Public_key = tk.Text(Pu_frame, height = 30, width = 64, font = ('SimSun', '11'), yscrollcommand=Pu_scrollbar.set) 
Text_Public_key.pack(side=tk.LEFT,fill=tk.BOTH)

Pu_scrollbar.config(command=Text_Public_key.yview)
#===(4.1.1)============↓=== Pu_frame end ===↓============(4.1.1)===#
Pu_frame.grid(row = 1, column = 0, columnspan=5)

#===(4.1.2)============↓=== Pi_frame start ===↓============(4.1.2)===#
Pi_frame = ttk.Frame(Gen_Key_tab, padding = 10)

Pi_scrollbar = tk.Scrollbar(Pi_frame)
Pi_scrollbar.pack(side=tk.RIGHT,fill=tk.Y)

Text_Private_key = tk.Text(Pi_frame, height = 30, width = 64, font = ('SimSun', '11'), yscrollcommand=Pi_scrollbar.set) 
Text_Private_key.pack(side=tk.LEFT,fill=tk.BOTH)

Pi_scrollbar.config(command=Text_Private_key.yview)
#===(4.1.2)============↓=== Pi_frame end ===↓============(4.1.2)===#
Pi_frame.grid(row = 1, column = 5, columnspan=5)
'''

#===(4.2)============↓=== Used_KeyPair_tab start ===↓============(4.2)===#

length_label = tk.Label(Used_KeyPair_tab, text="length: ")
length_label.grid(row = 0, column = 0)

key_length = tk.IntVar(value = 1024)
length_input=tk.Entry(Used_KeyPair_tab, width="10", textvariable=key_length)
length_input.grid(row = 0, column = 1)

ex_label = tk.Label(Used_KeyPair_tab, text="ex: ")
ex_label.grid(row = 0, column = 2)

key_ex = tk.IntVar(value = 65537)
ex_input=tk.Entry(Used_KeyPair_tab, width="10", textvariable=key_ex)
ex_input.grid(row = 0, column = 3)

Gen_Button = tk.Button(Used_KeyPair_tab ,text = "Random Gen Key", command = gen_rsa_key_pair)
Gen_Button.grid(row = 0, column = 4)

Im_pu_Button = tk.Button(Used_KeyPair_tab ,text = "Import from n, e", command = Import_pu)
Im_pu_Button.grid(row = 0, column = 5)

Im_both_Button = tk.Button(Used_KeyPair_tab ,text = "Import from n,e,d", command = import_both)
Im_both_Button.grid(row = 0, column = 6)

Pu_Label = tk.Label(Used_KeyPair_tab, text="Public Key")
Pu_Label.grid(row = 1, column = 2)
Pi_Label = tk.Label(Used_KeyPair_tab, text="Pirvate Key")
Pi_Label.grid(row = 1, column = 9)

#===(5.1)============↓=== Public_book start ===↓============(5.1)===#
Public_book = ttk.Notebook(Used_KeyPair_tab, padding = 10)

#Base64
Pu_Base64_tab = ttk.Frame(Public_book)
#Hex
Pu_Hex_tab = ttk.Frame(Public_book)

Text_Pu_Base64 = tk.Text(Pu_Base64_tab, height = 30, width = 64, font = ('SimSun', '11'))
Text_Pu_Base64.pack(side=tk.LEFT,fill=tk.BOTH)
Text_Pu_Hex = tk.Text(Pu_Hex_tab, height = 30, width = 64, font = ('SimSun', '11'))
Text_Pu_Hex.pack(side=tk.LEFT,fill=tk.BOTH)
#===(5.1)============↓=== Public_book end ===↓============(5.1)===#
Public_book.add(Pu_Base64_tab, text = 'Base64')
Public_book.add(Pu_Hex_tab, text = 'Hex')
Public_book.grid(row = 2, column = 0, columnspan=6)

#===(5.2)============↓=== Pirvate_book start ===↓============(5.2)===#
Pirvate_book = ttk.Notebook(Used_KeyPair_tab, padding = 10)

#Base64
Pi_Base64_tab = ttk.Frame(Pirvate_book)
#Hex
Pi_Hex_tab = ttk.Frame(Pirvate_book)
#Detail
Pi_detail_tab = ttk.Frame(Pirvate_book)


Text_Pi_Base64 = tk.Text(Pi_Base64_tab, height = 30, width = 64, font = ('SimSun', '11'))
Text_Pi_Base64.pack(side=tk.LEFT,fill=tk.BOTH)

Text_Pi_Hex = tk.Text(Pi_Hex_tab, height = 30, width = 64, font = ('SimSun', '11'))
Text_Pi_Hex.pack(side=tk.LEFT,fill=tk.BOTH)

#label of the name
n_label = tk.Label(Pi_detail_tab, text="n: ")
n_label.grid(row = 0, column = 0)
e_label = tk.Label(Pi_detail_tab, text="e: ")
e_label.grid(row = 2, column = 0)
d_label = tk.Label(Pi_detail_tab, text="d: ")
d_label.grid(row = 4, column = 0)
p_label = tk.Label(Pi_detail_tab, text="p: ")
p_label.grid(row = 6, column = 0)
q_label = tk.Label(Pi_detail_tab, text="q: ")
q_label.grid(row = 8, column = 0)
dp_label = tk.Label(Pi_detail_tab, text="dp: ")
dp_label.grid(row = 10, column = 0)
dq_label = tk.Label(Pi_detail_tab, text="dq: ")
dq_label.grid(row = 12, column = 0)
u_label = tk.Label(Pi_detail_tab, text="u: ")
u_label.grid(row = 14, column = 0)

#show the length of the component
n_len_label = tk.Label(Pi_detail_tab, text="u: ")
n_len_label.grid(row = 1, column = 0)
d_len_label = tk.Label(Pi_detail_tab)
d_len_label.grid(row = 5, column = 0)
p_len_label = tk.Label(Pi_detail_tab)
p_len_label.grid(row = 7, column = 0)
q_len_label = tk.Label(Pi_detail_tab)
q_len_label.grid(row = 9, column = 0)
dp_len_label = tk.Label(Pi_detail_tab)
dp_len_label.grid(row = 11, column = 0)
dq_len_label = tk.Label(Pi_detail_tab)
dq_len_label.grid(row = 13, column = 0)
u_len_label = tk.Label(Pi_detail_tab)
u_len_label.grid(row = 15, column = 0)

#show the component
n_Text = tk.Text(Pi_detail_tab, height = 5, width = 60, font = ('SimSun', '11'))
n_Text.grid(row = 0, column = 1, rowspan=2)
e_Text = tk.Text(Pi_detail_tab, height = 1, width = 60, font = ('SimSun', '11'))
e_Text.grid(row = 2, column = 1, rowspan=2)
d_Text = tk.Text(Pi_detail_tab, height = 5, width = 60, font = ('SimSun', '11'))
d_Text.grid(row = 4, column = 1, rowspan=2)
p_Text = tk.Text(Pi_detail_tab, height = 3, width = 60, font = ('SimSun', '11'))
p_Text.grid(row = 6, column = 1, rowspan=2)
q_Text = tk.Text(Pi_detail_tab, height = 3, width = 60, font = ('SimSun', '11'))
q_Text.grid(row = 8, column = 1, rowspan=2)
dp_Text = tk.Text(Pi_detail_tab, height = 3, width = 60, font = ('SimSun', '11'))
dp_Text.grid(row = 10, column = 1, rowspan=2)
dq_Text = tk.Text(Pi_detail_tab, height = 3, width = 60, font = ('SimSun', '11'))
dq_Text.grid(row = 12, column = 1, rowspan=2)
u_Text = tk.Text(Pi_detail_tab, height = 3, width = 60, font = ('SimSun', '11'))
u_Text.grid(row = 14, column = 1, rowspan=2)

#===(5.2)============↓=== Pirvate_book end ===↓============(5.2)===#
Pirvate_book.add(Pi_Base64_tab, text = 'Base64')
Pirvate_book.add(Pi_Hex_tab, text = 'Hex')
Pirvate_book.add(Pi_detail_tab, text = 'Details')
Pirvate_book.grid(row = 2, column = 6, columnspan=6)


#===(4.3)============↓=== Encry_Decry_tab start ===↓============(4.3)===#
Encry = tk.Button(Encry_Decry_tab ,text = "Encry", command = public_encryption)
Encry.grid(row = 0, column = 0)

Decry = tk.Button(Encry_Decry_tab ,text = "Decry", command = Private_decryption)
Decry.grid(row = 0, column = 1)

In_Label = tk.Label(Encry_Decry_tab, text="Decryted Data")
In_Label.grid(row = 1, column = 0)
Out_Label = tk.Label(Encry_Decry_tab, text="Encryted Data")
Out_Label.grid(row = 1, column = 1)

#===(5.1)============↓=== Decryted_book start ===↓============(5.1)===#
Decryted_book = ttk.Notebook(Encry_Decry_tab, padding = 10)

#Base64
De_Base64_tab = ttk.Frame(Decryted_book)
#Hex
De_Hex_tab = ttk.Frame(Decryted_book)

De_B64_Text = tk.Text(De_Base64_tab, height = 30, width = 64, font = ('SimSun', '11'))
De_B64_Text.bind('<FocusOut>', lambda e, De_B64_Text = De_B64_Text : Base64_to_Hex(De_B64_Text.get(1.0,tk.END),De_Hex_Text))
De_B64_Text.pack(side=tk.LEFT,fill=tk.BOTH)

De_Hex_Text = tk.Text(De_Hex_tab, height = 30, width = 64, font = ('SimSun', '11'))
De_Hex_Text.bind('<FocusOut>', lambda e, De_Hex_Text = De_Hex_Text : Hex_to_Base64(De_Hex_Text.get(1.0,tk.END),De_B64_Text))
De_Hex_Text.pack(side=tk.LEFT,fill=tk.BOTH)


#===(5.1)============↓=== Decryted_book end ===↓============(5.1)===#
Decryted_book.add(De_Hex_tab, text = 'Hex')
Decryted_book.add(De_Base64_tab, text = 'Base64')
Decryted_book.grid(row = 2, column = 0)

#===(5.2)============↓=== Encry_book start ===↓============(5.2)===#
Encry_book = ttk.Notebook(Encry_Decry_tab, padding = 10)

#Base64
En_Base64_tab = ttk.Frame(Encry_book)
#Hex
En_Hex_tab = ttk.Frame(Encry_book)

En_B64_Text = tk.Text(En_Base64_tab, height = 30, width = 64, font = ('SimSun', '11'))
En_B64_Text.bind('<FocusOut>', lambda e, En_B64_Text = En_B64_Text : Base64_to_Hex(En_B64_Text.get(1.0,tk.END),En_Hex_Text))
En_B64_Text.pack(side=tk.LEFT,fill=tk.BOTH)
En_Hex_Text = tk.Text(En_Hex_tab, height = 30, width = 64, font = ('SimSun', '11'))
En_Hex_Text.bind('<FocusOut>', lambda e, En_Hex_Text = En_Hex_Text : Hex_to_Base64(En_Hex_Text.get(1.0,tk.END),En_B64_Text))
En_Hex_Text.pack(side=tk.LEFT,fill=tk.BOTH)

#===(5.2)============↓=== Encry_book end ===↓============(5.2)===#
Encry_book.add(En_Hex_tab, text = 'Hex')
Encry_book.add(En_Base64_tab, text = 'Base64')
Encry_book.grid(row = 2, column = 1)


#===(4)============↓=== RSA_book end ===↓============(4)===#
#RSA_book.add(Gen_Key_tab, text = 'Gen_Key')
RSA_book.add(Used_KeyPair_tab, text = 'Used Key Pair')
RSA_book.add(Encry_Decry_tab, text = 'PKCS#1 1.5')
RSA_book.pack()

#===(3)============↓=== Main_Book end ===↓============(3)===#
Main_Book.add(RSA_tab, text = 'RSA')
Main_Book.add(DES_tab, text = 'DES')
Main_Book.pack()

#===(2)============↓=== Main_frame end ===↓============(2)===#
Main_frame.pack()

#===(1)============↓=== Main_Windows end ===↓============(1)===#
Main_Windows.mainloop()









