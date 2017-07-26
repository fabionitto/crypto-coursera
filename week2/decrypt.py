from Crypto.Cipher import AES

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def decrypt_CBC_AES(key, ct):
    iv = ct[0:16]
    c = ct[16:]
    blocks = len(c)/16
    pt = ''

    cipher = AES.new(key,AES.MODE_ECB)

    c1 = iv
    for i in range(blocks):
         print "Round:" , i
         cn, c = c[0:16], c[16:] 
         d = cipher.decrypt(cn)
         pt += strxor(c1, d)
         c1 = cn       
   
    return pt

def decrypt_CTR_AES(key, ct):
    nonce = ct[0:8]
    counter = ct[8:16]
    c = ct[16:]
    blocks = len(c)/16

    pt = ''
    cipher = AES.new(key,AES.MODE_ECB)
    for i in range(blocks+1):
        print "Round: ", i
        cn, c = c[0:16], c[16:]
        d = cipher.encrypt(nonce + counter)
        ncounter = hex(int(counter.encode('hex'),16) + 1)[2:]        
        if len(counter) % 2 == 1:
            counter = '0'+counter
        counter = ncounter.decode('hex')  
        pt += strxor(cn,d)
    
    return pt

def main():
    cbc_key = '140b41b22a29beb4061bda66b6747e14'
    ctr_key = '36f18357be4dbd77f050515c73fcf9f2'

    cbc1 = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
    cbc2 = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
    ctr1 = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'
    ctr2 = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'
    
    pt1 = decrypt_CBC_AES(cbc_key.decode('hex'), cbc1.decode('hex'))
    pt2 = decrypt_CBC_AES(cbc_key.decode('hex'), cbc2.decode('hex'))
    pt3 = decrypt_CTR_AES(ctr_key.decode('hex'), ctr1.decode('hex'))
    pt4 = decrypt_CTR_AES(ctr_key.decode('hex'), ctr2.decode('hex'))

    print "CBC PT 1:", pt1
    print "CBC PT 2:", pt2
    print "CTR PT 1:", pt3
    print "CTR PT 2:", pt4


if __name__ == "__main__":
    main()
