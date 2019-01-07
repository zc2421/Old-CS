#MA398
#Test2 Part2
#Implement Elgamal public key cryptosystem using elliptic curves
#I used the elliptic curve E: y^2 = x^3 + 65x
#I used the point P = (66, 4194156215919852944432610403656815189835385983687492285858733749758902176375603518107256187245165021073357647135734783287470291545656402126681825498447605100954125377559083612644353541733013977698155756291552475108377060866382062919800362936451658549337230412753570475693248717197348154016989679148484322991320658973180488757828128887634230980734556277547172713452702431437866552308150314030085052266251119504898008104626103777284430230295442120131278945718037328995928346494464532236735129940699803747745679246180432019374135523601239508909048125183207586133938318853801928092488753882070244698630934264479044142379)
#Zilin Chen
#4/23/2017


import RSA
import cryptomath
import random

import sys  



A = 65
p = 16952812084237229742549447635777009457935099242591652843352409095695787308344566841077820998719633577915786743997298880022410678326314806928952044861346435573063172933676651387002359348672542580489846953464995824634217832849270171792666945559945713037832356034663463033027556222519297389540623186698989678960029897715317483824072431510638121355505739110562404763808387752092724610378021431021189732771387597216883239188515173762718922995837157662813147918321297110209645440763320059363915029096783439088084955838933065493654884609613131036345222479336417641259553586407226315641330017349452555492286684677695714022999
P = [66, 4194156215919852944432610403656815189835385983687492285858733749758902176375603518107256187245165021073357647135734783287470291545656402126681825498447605100954125377559083612644353541733013977698155756291552475108377060866382062919800362936451658549337230412753570475693248717197348154016989679148484322991320658973180488757828128887634230980734556277547172713452702431437866552308150314030085052266251119504898008104626103777284430230295442120131278945718037328995928346494464532236735129940699803747745679246180432019374135523601239508909048125183207586133938318853801928092488753882070244698630934264479044142379]


def findPoint():
	x = 20
	while x < 50:
		val = (pow(x,3) + 65*x)%p
		if cryptomath.isSquare(val,p):
			y = cryptomath.modularSqrt(val,p)
			print(x,y)

		x +=1

def generateKeys():
    # Generates public and private keys and saves them to a file.

    #private key
    n_a = random.randint(2,p-1)
    #print (n_a)

    #public key
    Q_a = cryptomath.ellipticCurveMultiplication([A,0], p, P, n_a)
    #print (Q_a)

    #save them to a file
    fo = open('my_elgamal_public_key.txt', 'w')
    fo.write('%s, %s' % (Q_a[0],Q_a[1]))
    fo.close()
    fo = open('my_elgamal_private_key.txt', 'w')
    fo.write('%s' % (n_a))
    fo.close()




def elgamalEncrypt(messageFilename, publicKeyFilename):
    fo = open(messageFilename, 'r')
    plaintext = fo.read()
    fo.close()
    #print('%s\n\n%s\n%s\n%s\n' %('Text to encrypt:', '***', plaintext, '***'))


    blocks = RSA.textToBlocks(plaintext)
    #print('%s\n\n%s\n' %('Text blocks:', blocks))
    numbers = RSA.blocksToNumbers(blocks)
    print('%s\n\n%s\n' %('Blocks as numbers:', numbers))


    fo = open(publicKeyFilename, 'r')
    content = fo.read()
    fo.close()
    x, y = content.split(',')
    Q_a = [int(x), int(y)]
    #print ( Q_a )

    #choose ephemeral key
    n_b = random.randint(2,p-1)
    #print(n_b)
    c1 = cryptomath.ellipticCurveMultiplication([A,0], p, P, n_b)
    #print (c1)

    #turn message into points on elliptic curve
    encryptedPoints, mapping = encodeAsAPoints(numbers,A,p)

    s_mapping = ''
    for val in mapping:
        s_mapping += str(val)
    #print (s_mapping)

    #print ('test block:', encryptedPoints)
    #print ('test mapping', mapping )

    c2 = []
    nb_Qa = cryptomath.ellipticCurveMultiplication([A,0], p, Q_a, n_b)

    #print (nb_Qa)

    for m in encryptedPoints:
    	#print (m)
    	pt = cryptomath.ellipticCurveAddition([A,0] , p, [m,nb_Qa] )
    	c2.append( pt )

    #print (c2)

    
    encryptedFile = open('elgamal_message_encrypted.txt', 'w')
    encryptedFile.write('%s, %s' % (c1[0],c1[1]))
    encryptedFile.write('\n')
    for pt in c2:
    	encryptedFile.write('%s, %s' % (pt[0],pt[1]))
    	encryptedFile.write('\n')
    encryptedFile.write('%s' % (s_mapping))
    encryptedFile.close()
    






def elgamalDecrypt(messageFilename, privateKeyFilename):
    fo = open(messageFilename, 'r')
    content = fo.read()
    fo.close()
    #print (content)

    lis = content.split('\n')
    s_mapping = lis.pop()
    mapping = []
    for i in range (len(s_mapping)):
        mapping.append(int(s_mapping[i]))
    #print ('test :', mapping)


    x,y = lis[0].split(',')
    c1 = [int(x), int(y)]
    #print (c1)

    c2 = []
    lis = lis[1:]
    for s in lis:
    	x,y = s.split(',')
    	pt = [int(x), int(y)]
    	c2.append(pt)
    #print (c2)

    fo = open(privateKeyFilename, 'r')
    content = fo.read()
    fo.close()
    n_a = int(content)
    #print (n_a)


    na_c1 = cryptomath.ellipticCurveMultiplication([A,0], p, c1, n_a)
    #print (na_c1)
    na_c1_neg = [na_c1[0], -na_c1[1]]
    #print (na_c1_neg)

    message = []
    for pt in c2:
    	m = cryptomath.ellipticCurveAddition([A,0], p, [pt,na_c1_neg])
    	message.append(m[0])
    
    for i in range(len(mapping)):
        if mapping[i] == 1:
            message[i] = p - message[i]

    #print ('\ntest message', message)

    blocks = []
    for x in message:
        digits = cryptomath.base_b_digits(x, 256)
        textBlock = ''
        for d in digits:
            textBlock += chr(d)
        blocks.append(textBlock)
    plaintext = ''.join(blocks)
    print('%s\n%s\n%s\n%s' %('Decrypted text:', '***', plaintext, '***'))   



def encodeAsAPoints(numbers,a,p):

    lis = []
    mapping = []

    for n in numbers:

        val = ( pow(n,3) + a*n ) % p

        if cryptomath.isSquare(val, p):
            y = cryptomath.modularSqrt(val, p)
            lis.append([n,y])
            mapping.append(0)

        else:
        	val2 = ( -pow(n,3) - a*n ) % p
        	y = cryptomath.modularSqrt(val2, p)
        	lis.append([-n,y])
        	mapping.append(1)

    return lis,mapping



#generateKeys()
#elgamalEncrypt('message.txt', 'my_elgamal_public_key.txt')
#elgamalDecrypt('elgamal_message_encrypted.txt', 'my_elgamal_private_key.txt')


