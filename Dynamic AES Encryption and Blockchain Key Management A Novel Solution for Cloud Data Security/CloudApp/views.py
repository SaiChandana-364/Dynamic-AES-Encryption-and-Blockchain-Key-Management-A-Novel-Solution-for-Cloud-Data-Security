from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from datetime import date
import os
import json
from web3 import Web3, HTTPProvider
from django.core.files.storage import FileSystemStorage
import pickle
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
from hashlib import sha256
import io
import numpy as np
import cv2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import ftplib
import pyaes, pbkdf2, binascii, secrets
import base64
import timeit

global usersList, fileList

#function to call contract
def getContract():
    global contract, web3
    blockchain_address = 'http://127.0.0.1:8545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'SmartContract.json' #Smart Contract to manage user file details
    deployed_contract_address = '0xF88351E8b55767c6b0B77119071E3fC2417e3663' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
getContract()

def getUsersList():
    global usersList, contract
    usersList = []
    count = contract.functions.getUserCount().call()
    for i in range(0, count):
        user = contract.functions.getUsername(i).call()
        password = contract.functions.getPassword(i).call()
        phone = contract.functions.getPhone(i).call()
        email = contract.functions.getEmail(i).call()
        address = contract.functions.getAddress(i).call()
        usersList.append([user, password, phone, email, address])

def getFileList():
    global fileList, contract
    fileList = []
    count = contract.functions.getFileCount().call()
    for i in range(0, count):
        user = contract.functions.getUser(i).call()
        file = contract.functions.getFilename(i).call()
        sharing = contract.functions.getSharing(i).call()
        keys = contract.functions.getKeys(i).call()
        dd = contract.functions.getDate(i).call()
        fileList.append([user, file, sharing, keys, dd])
getUsersList()
getFileList()

#function to generate public and private keys for ECC algorithm
def ECCGenerateKeys():
    if os.path.exists("pvt.key"):
        with open("pvt.key", 'rb') as f:
            private_key = f.read()
        f.close()
        with open("pri.key", 'rb') as f:
            public_key = f.read()
        f.close()
        private_key = private_key.decode()
        public_key = public_key.decode()
    else:
        secret_key = generate_eth_key()
        private_key = secret_key.to_hex()  # hex string
        public_key = secret_key.public_key.to_hex()
        with open("pvt.key", 'wb') as f:
            f.write(private_key.encode())
        f.close()
        with open("pri.key", 'wb') as f:
            f.write(public_key.encode())
        f.close()
    return private_key, public_key

#ECC will encrypt data using plain text adn public key
def ECCEncrypt(plainText, public_key):
    cpabe_encrypt = encrypt(public_key, plainText)
    return cpabe_encrypt

#ECC will decrypt data using private key and encrypted text
def ECCDecrypt(encrypt, private_key):
    cpabe_decrypt = decrypt(private_key, encrypt)
    return cpabe_decrypt

def getAESDynamicKey(file_hash, block_hash): #generating AES key based on Diffie common secret shared key
    key = bytes(x ^ y for x, y in zip(result1, result2))
    return key

def AESencrypt(plaintext, key): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    enc = aes.encrypt(plaintext)
    return enc

def AESdecrypt(enc, key): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted    

def Graph(request):
    if request.method == 'GET':
        img = cv2.imread("CloudApp/static/images/images_1.jpg")
        dtypes = img.dtype
        height, width, channel = img.shape
        size = height * width * channel
        hist1 = np.histogram(img.ravel(), density=True)
        data = hist1[0]
        existing_entropy = -(data*np.log(np.abs(data))).sum()
        existing_hist = img.ravel()

        img = img.tobytes()
        ivSize = 0
        with open("CloudApp/static/images/images_1.jpg", "rb") as file:
            data = file.read()
        file.close()
        result1 = sha256(img).digest()
        result2 = sha256(img[0:30]).digest()
        key = bytes(x ^ y for x, y in zip(result1, result2))
        start = timeit.default_timer()
        imageOrigBytesPadded = pad(img, AES.block_size)
        aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
        ciphertext = aes.encrypt(imageOrigBytesPadded)
        end = timeit.default_timer()
        aes_time = end - start
        start = timeit.default_timer()
        cha_key = get_random_bytes(32)
        cha_cipher = ChaCha20.new(key=cha_key)
        chacha_encrypt = cha_cipher.encrypt(img)
        end = timeit.default_timer()
        chacha_time = end - start

        paddedSize = len(imageOrigBytesPadded) - len(img)
        void = height * channel - ivSize - paddedSize
        ivCiphertextVoid = key + ciphertext + bytes(void)
        ivCiphertextVoid = ivCiphertextVoid[0:size]
        imageEncrypted = np.frombuffer(ivCiphertextVoid, dtype = dtypes).reshape(height, width, channel)

        hist1 = np.histogram(imageEncrypted.ravel(), density=True)
        data = hist1[0]
        propose_entropy = -(data*np.log(np.abs(data))).sum()
        propose_hist = imageEncrypted.ravel()

        output = '<table border=1 align=center>'
        output+='<tr><th><font size=3 color=black>Algorithm Name</font></th>'
        output+='<th><font size=3 color=black>Sensitivity</font></th></tr>'
        output+='<tr><td><font size=3 color=black>Existing Algorithm</font></td>'
        output+='<td><font size=3 color=black>'+str(existing_entropy)+'</font></td></tr>'
        output+='<tr><td><font size=3 color=black>Propose Algorithm</font></td>'
        output+='<td><font size=3 color=black>'+str(propose_entropy)+'</font></td></tr>'
        output+='<tr><td><font size=3 color=black>AES Encryption Time : '+str(round(aes_time, 4))+'</font></td>'
        output+='<td><font size=3 color=black>Extension CHA-CHA Encryption Time : '+str(round(chacha_time, 4))+'</font></td></tr>'
        output+="</table><br/>"
        figure, axis = plt.subplots(nrows=1, ncols=4,figsize=(12,6))
        axis[0].set_title("Original Image")
        axis[1].set_title("Histogram")
        axis[2].set_title("Encrypted Image")
        axis[3].set_title("Encrypted Histogram")
        axis[0].imshow(cv2.imread("CloudApp/static/images/images_1.jpg"))
        axis[1].hist(existing_hist)
        axis[2].imshow(imageEncrypted)
        axis[3].hist(propose_hist)
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        plt.close()
        img_b64 = base64.b64encode(buf.getvalue()).decode()    
        context= {'data':output, 'img': img_b64}
        return render(request, 'UserScreen.html', context)   

def index(request):
    if request.method == 'GET':
       return render(request, 'index.html', {})

def Login(request):
    if request.method == 'GET':
       return render(request, 'Login.html', {})

def Signup(request):
    if request.method == 'GET':
       return render(request, 'Signup.html', {})

def UploadFile(request):
    if request.method == 'GET':
       global username, contract, fileList
       count = contract.functions.getUserCount().call()
       status = '<tr><td><font size="3" color="black">Sharing&nbsp;Users</b></td><td><select name="t1" multiple>'
       for i in range(0, count):
           user = contract.functions.getUsername(i).call()
           if user != username:
               status += '<option value="'+user+'">'+user+'</option>'               
       status += '</select></td></tr>'
       context = {'data1':status}
       return render(request, 'UploadFile.html', context)

def getData(filename):
    with open("CloudApp/static/files/"+filename, "rb") as file:
        data = file.read()
    file.close()
    
    session = ftplib.FTP('64.227.130.104','ftpuser','aes')
    file = open("CloudApp/static/files/"+filename,'rb')                  # file to send
    session.storbinary("CloudApp/static/files/"+filename, file)     # send the file 
    file.close()                                    # close file and FTP
    session.quit()
    return data

def DownloadFileDataRequest(request):
    if request.method == 'GET':
        global fileList
        index = request.GET.get('hash', False)
        index = int(index)
        flist = fileList[index]
        keys = base64.b64decode(flist[3])
        aes_decrypt = AESdecrypt(getData(flist[1]), keys)
        private_key, public_key = ECCGenerateKeys()
        decrypted = ECCDecrypt(aes_decrypt, private_key)
        response = HttpResponse(decrypted,content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename='+flist[1]
        return response        
            
def DownloadFile(request):
    if request.method == 'GET':
        global username, fileList
        strdata = '<table border=1 align=center width=100%><tr><th><font size="" color="black">Data Owner</th>'
        strdata+='<th><font size="" color="black">Filename</th><th><font size="" color="black">Sharing User</th>'
        strdata+='<th><font size="" color="black">Encrypted AES Key</th><th><font size="" color="black">Upload Date</th>'
        strdata+='<th><font size="" color="black">Download File</th></tr>'
        for i in range(len(fileList)):
            flist = fileList[i]
            array = flist[2].split(" ")
            if username in array:
                strdata+='<tr><td><font size="" color="black">'+str(flist[0])+'</td><td><font size="" color="black">'+flist[1]+'</td><td><font size="" color="black">'+str(flist[2])+'</td>'
                strdata+='<td><font size="" color="black">'+str(flist[3])+'</td>'
                strdata+='<td><font size="" color="black">'+str(flist[4])+'</td>'
                strdata+='<td><a href=\'DownloadFileDataRequest?hash='+str(i)+'\'><font size=3 color=black>Download File</font></a></td></tr>'                
        context= {'data':strdata}
        return render(request, 'ViewSharedMessages.html', context)        
         

def UploadFileAction(request):
    if request.method == 'POST':
        global username, contract, fileList
        sharing = request.POST.getlist('t1')
        shares = ""
        for i in range(len(sharing)):
            shares+=sharing[i]+" "
        shares = shares+username    
        filename = request.FILES['t2'].name
        myfile = request.FILES['t2'].read()
        file_hash = sha256(myfile).digest()
        block = myfile[0:30]
        block_hash = sha256(block).digest()
        aes_dynamic_key = bytes(x ^ y for x, y in zip(file_hash, block_hash))        
        private_key, public_key = ECCGenerateKeys()
        ecc_encrypt = ECCEncrypt(myfile, public_key)
        aes_encrypt = AESencrypt(ecc_encrypt, aes_dynamic_key)
        with open("CloudApp/static/files/"+filename, "wb") as file:
            file.write(aes_encrypt)
        file.close()
        aes_dynamic_key = base64.b64encode(aes_dynamic_key).decode()
        print("string "+str(aes_dynamic_key))
        msg = contract.functions.createFile(username, filename, shares, aes_dynamic_key, str(date.today())).transact()
        fileList.append([username, filename, shares, aes_dynamic_key, str(date.today())])
        tx_receipt = web3.eth.waitForTransactionReceipt(msg)
        context= {'data':'File successfuly encrypted using AES & ECC and saved in Cloud & Blockchain<br/>'+str(tx_receipt)}
        return render(request, 'UserScreen.html', context) 

def SignupAction(request):
    if request.method == 'POST':
        global usersList, contract
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        gender = request.POST.get('t4', False)
        email = request.POST.get('t5', False)
        address = request.POST.get('t6', False)
        count = contract.functions.getUserCount().call()
        status = "none"
        for i in range(0, count):
            user1 = contract.functions.getUsername(i).call()
            if username == user1:
                status = "exists"
                break
        if status == "none":
            msg = contract.functions.createUser(username, password, contact, email, address).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(msg)
            usersList.append([username, password, contact, email, address])
            context= {'data':'New user signup details completed<br/>'+str(tx_receipt)}
            return render(request, 'Signup.html', context)
        else:
            context= {'data':'Given username already exists'}
            return render(request, 'Signup.html', context)

def LoginAction(request):
    if request.method == 'POST':
        global username, contract, usersList, usertype
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        status = "Login.html"
        output = 'Invalid login details'
        for i in range(len(usersList)):
            ulist = usersList[i]
            user1 = ulist[0]
            pass1 = ulist[1]
            if user1 == username and pass1 == password:
                output = 'Welcome '+username
                status = 'UserScreen.html'                
                break            
        context= {'data':output}
        return render(request, status, context)








        


