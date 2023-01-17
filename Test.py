# Importing flask module in the project is mandatory
# An object of Flask class is our WSGI application.
from flask import Flask, render_template, request
from monoalphabetic import mono_alphabetic
from Playfair import playfair
from numpy.linalg import inv
# Flask constructor takes the name of
# current module (__name__) as argument.
app = Flask(__name__, template_folder = "Templates")
def egcd(a, b):
	x,y, u,v = 0,1, 1,0
	while a != 0:
		q, r = b//a, b%a
		m, n = x-u*q, y-v*q
		b,a, x,y, u,v = a,r, u,v, m,n
	gcd = b
	return gcd, x, y

def modinv(a, m):
	gcd, x, y = egcd(a, m)
	if gcd != 1:
		return None # modular inverse does not exist
	else:
		return x % m

def affine_encrypt(text, key):
	return ''.join([ chr((( key[0]*(ord(t) - ord('A')) + key[1] ) % 26)
				+ ord('A')) for t in text.upper().replace(' ', '') ])

def affine_decrypt(cipher, key):
	return ''.join([ chr((( modinv(key[0], 26)*(ord(c) - ord('A') - key[1]))
					% 26) + ord('A')) for c in cipher ])

def generateKey(string, key):
    key = list(key)
    if len(string) == len(key):
        return(key)
    else:
        for i in range(len(string) -
                       len(key)):
            key.append(key[i % len(key)])
    return("" . join(key))
     

def cipherText(string, key):
    cipher_text = []
    for i in range(len(string)):
        x = (ord(string[i]) +
             ord(key[i])) % 26
        x += ord('A')
        cipher_text.append(chr(x))
    return("" . join(cipher_text))
     

def originalText(cipher_text, key):
    orig_text = []
    for i in range(len(cipher_text)):
        x = (ord(cipher_text[i]) -
             ord(key[i]) + 26) % 26
        x += ord('A')
        orig_text.append(chr(x))
    return("" . join(orig_text))

def HillCipher(message, key0, mode = "e"):

    text = ""

    n = len(message)
    key = key0
    r = 0
    while(len(key) < n**2):
        key = key + key[r]
        r = (r+1)%len(key0)

    keyMatrix = [[0] * n for i in range(n)]
    kM = [[0] * n for i in range(n)]
    kMI = [[0] * n for i in range(n)]

    # Generate vector for the message
    messageVector = [[0] for i in range(n)]

    # Generate vector for the cipher
    cipherMatrix = [[0] for i in range(n)]

    # Following function generates the
    # key matrix for the key string
    def getKeyMatrix(key):
        k = 0
        text = "Key Matrix: \n["
        for i in range(n):
            text += "["
            for j in range(n):
                kM[i][j] = ord(key[k]) % 65
                k += 1
                text += str(kM[i][j])
                if (j < n-1):
                    text += ","
            text += "]"
        text += "] \n"
        kMI = inv(kM)
        #text += "Inverse Key Matrix: \n["
        #for i in range(n):
        #    text += "["
        #    for j in range(n):
        #        text += str(kMI[i][j])
        #        if (j < n-1):
        #            text += ","
        #    text += "]"
        #text += "] \n"
        return text

    # Following function encrypts the message
    def encrypt(messageVector):
        for i in range(n):
            for j in range(1):
                cipherMatrix[i][j] = 0
                for x in range(n):
                    cipherMatrix[i][j] += (keyMatrix[i][x] *
                                        messageVector[x][j])
                cipherMatrix[i][j] = cipherMatrix[i][j] % 26

    # Get key matrix from the key string
    text += getKeyMatrix(key)
    if (mode == "e"):
        keyMatrix = kM
    else:
        keyMatrix = kMI

    # Generate vector for the message
    for i in range(n):
        messageVector[i][0] = ord(message[i]) % 65

    # Following function generates
    # the encrypted vector
    encrypt(messageVector)

    # Generate the encrypted text
    # from the encrypted vector
    CipherText = []
    text += "Ciphertext: "
    for i in range(n):
        CipherText.append(chr(cipherMatrix[i][0] + 65))
        text += CipherText[i]

    # Finally print the ciphertext
    # print("Ciphertext: ", "".join(CipherText))
    return text

# The route() function of the Flask class is a decorator,
# which tells the application which URL should call
# the associated function.
@app.route('/')
# ‘/’ URL is bound with hello_world() function.
def home():
	return render_template("Main.html")

@app.route('/submit', methods=['post'])
def submit():
    #return render_template("Test.html")
    a = int(request.form['a'])
    b = int(request.form['b'])
    key = [a,b]
    text = request.form['var']
    #create variable that get the value of encrypt_Decrypt
    encrypt_Decrypt = request.form.get('encrypt_Decrypt')
    print(encrypt_Decrypt)
    if encrypt_Decrypt == None:
        print("decrypt")
        enc = "Your Decrypted message is: " + affine_decrypt(text,key)
    else:
        print("encrypt")
        enc = "Your Encrypted message is: " + affine_encrypt(text,key)

    return render_template("Main.html",output= enc)


@app.route('/inverse', methods=['post'])
def inverse():
    a = int(request.form['A_inverse'])
    b = int(request.form['B_inverse'])
    inv = modinv(a,b)
    if inv == None:
        res = "No Modular inverse for" + str(a)
    else:
        res = "Modular Inverse of " + str(a) + " Modulo " + str(b) + " is " + str(inv)
    return render_template("Main.html",output1= res)


@app.route('/vigenere', methods=['post'])
def vigenere():
    #get value of encrypt_Decrypt2 
    encrypt_Decrypt2 = request.form.get('encrypt_Decrypt2')
    #check the value of encrypt_Decrypt2 an if 1 then encrypt else decrypt
    if encrypt_Decrypt2 == None:
        print("decrypt")
        key = generateKey(request.form['text'],request.form['KeyWord'])
        text = originalText(request.form['text'],key)
        
    else:
        print("encrypt")
        key = generateKey(request.form['text'],request.form['KeyWord'])
        text = cipherText(request.form['text'],key)

    return render_template("Main.html",output2= text)


m=mono_alphabetic()
@app.route('/monoalphabetic_enc', methods=['post'])
def monoalphabetic_enc():
    cipherText=m.encrypt(request.form['KeyWord'])
    return render_template("Main.html",mono_cipher=cipherText)


@app.route('/monoalphabetic_dec', methods=['post'])
def monoalphabetic_dec():
    plainText=m.decrypt(request.form['KeyWord'])
    return render_template("Main.html",mono_plain=plainText)


#impletment playfair

@app.route('/playfair_enc', methods=['post'])
def playfair_enc():
    key = str(request.form['KeyWord'])
    print(key)
    plain = str(request.form['plain'])
    print(plain)
    cipherText=playfair(key,plain,True)
    print(cipherText)
    return render_template("Main.html",output3=cipherText)

#impletment playfair
@app.route('/playfair_dec', methods=['post'])
def playfair_dec():
    key = request.form['KeyWord']
    plain = request.form['cipher']
    plainText=playfair(key,plain,False)
    return render_template("Main.html",output4=plainText)

@app.route('/hill', methods=['post'])
def hill():
    text = request.form['hill_text']
    key = request.form['hill_key']
    t = HillCipher(text, key)
    return render_template("Main.html",output5 = t)

# main driver function
if __name__ == '__main__':

	# run() method of Flask class runs the application
	# on the local development server.
	app.run()


