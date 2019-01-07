# Basic implementation of RSA encryption

import cryptomath, random

BLOCKSIZE = 12

def generateKeys():
    # Generates public and private keys and saves them to a file.
    p, q = [cryptomath.findPrime(), cryptomath.findPrime()]
    phi = (p - 1)*(q - 1)
    n = p*q
    foundEncryptionKey = False
    while not foundEncryptionKey:
        e = random.randint(2, phi - 1)
        if cryptomath.gcd(e, phi) == 1:
            foundEncryptionKey = True
    d = cryptomath.findModInverse(e, phi)
    fo = open('my_rsa_public_key.txt', 'w')
    fo.write('%s, %s' % (n,e))
    fo.close()
    fo = open('my_rsa_private_key.txt', 'w')
    fo.write('%s, %s' % (n,d))
    fo.close()

def textToBlocks(plaintext):
    # Breaks up the plaintext into blocks.
    textLength = len(plaintext)
    lastBlockLength = textLength % BLOCKSIZE
    fullBlocks = (textLength - lastBlockLength) // BLOCKSIZE
    blocks = []
    for i in range(fullBlocks):
        thisBlock = ''
        m = i*BLOCKSIZE
        for j in range(BLOCKSIZE):
            thisBlock += plaintext[m + j]
        blocks.append(thisBlock)
    if lastBlockLength > 0:
        lastBlock = ''
        m = fullBlocks*BLOCKSIZE
        for j in range(lastBlockLength):
            lastBlock += plaintext[m + j]
        blocks.append(lastBlock)
    return blocks
        
def blocksToNumbers(blockList):
    # Converts a list of text blocks into a list of numbers.
    numbers = []
    for block in blockList:
        N = 0
        encodedBlock = list(block.encode('ascii'))
        for i in range(len(block)):
            N += encodedBlock[i]*(256**i)
        numbers.append(N)
    return numbers

def rsaEncrypt(messageFilename, publicKeyFilename):
    fo = open(messageFilename, 'r')
    plaintext = fo.read()
    fo.close()
    #print('%s\n\n%s\n%s\n%s\n' %('Text to encrypt:', '***', plaintext, '***'))
    blocks = textToBlocks(plaintext)
    #print('%s\n\n%s\n' %('Text blocks:', blocks))
    numbers = blocksToNumbers(blocks)
    #print('%s\n\n%s\n' %('Blocks as numbers:', numbers))
    fo = open(publicKeyFilename, 'r')
    content = fo.read()
    fo.close()
    n, e = content.split(',')
    n, e = int(n), int(e)
    encryptedNumbers = []
    for x in numbers:
        encryptedNumbers.append(pow(x,e,n))
    ciphertext = []
    for i in encryptedNumbers:
        ciphertext.append(str(i))
    ciphertext = ','.join(ciphertext)
    encryptedFile = open('rsa_message_encrypted.txt', 'w')
    encryptedFile.write(ciphertext)
    encryptedFile.close()
    print('%s\n\n%s' %('Encrypted message saved to file:', ciphertext))

def base_b_digits(x, b):
    # Builds a list of the base-b digits of x.
    digits = []
    n = x
    while(n > 0):
        r = n % b
        digits.append(r)
        n = (n - r) // b
    return digits

def rsaDecrypt(messageFilename, privateKeyFilename):
    fo = open(messageFilename, 'r')
    content = fo.read()
    fo.close()
    encryptedNumbers = content.split(',')
    for i in range(len(encryptedNumbers)):
        encryptedNumbers[i] = int(encryptedNumbers[i])
    fo = open(privateKeyFilename, 'r')
    content = fo.read()
    fo.close()
    n, d = content.split(',')
    n, d = int(n), int(d)
    decryptedNumbers = []
    for y in encryptedNumbers:
        decryptedNumbers.append(pow(y,d,n))
    blocks = []
    for x in decryptedNumbers:
        digits = base_b_digits(x, 256)
        textBlock = ''
        for d in digits:
            textBlock += chr(d)
        blocks.append(textBlock)
    plaintext = ''.join(blocks)
    print('%s\n%s\n%s\n%s' %('Decrypted text:', '***', plaintext, '***'))   
    


#generateKeys()
#rsaEncrypt('message.txt','my_rsa_public_key.txt')
