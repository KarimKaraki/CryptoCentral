import random

class mono_alphabetic:
    initial=["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"]
    enc_mapping={}
    dec_mapping={}
    def __init__(self):
        self.randomized=self.initial.copy()
        random.shuffle(self.randomized)
        for i in range(len(self.initial)):
            self.enc_mapping[self.initial[i]]=self.randomized[i]
            self.dec_mapping[self.randomized[i]]=self.initial[i]

    def encrypt(self,plaintext):
        ciphertext=""
        self.is_upper=[]
        for i in range(len(plaintext)):
            if(plaintext[i].isupper()):
                self.is_upper.append(True)
            else:
                self.is_upper.append(False)

        plaintext=plaintext.lower()

        for i in plaintext:
            if i in self.initial:
                ciphertext+=self.enc_mapping[i]
            else:
                ciphertext+=i

        return ciphertext
        
    def decrypt(self,ciphertext):
        plaintext=""
        for i in range(len(ciphertext)):
            if ciphertext[i] in self.initial:
                p=""
                if self.is_upper[i]:
                    p=self.dec_mapping[ciphertext[i]].upper()
                else:
                    p=self.dec_mapping[ciphertext[i]]
                plaintext+=p
            else:
                plaintext+=ciphertext[i]
            
        return plaintext




