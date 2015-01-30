#!/usr/bin/env python
# Joric/bitcoin-dev, june 2012, public domain

import hashlib
import ctypes
import ctypes.util
import datetime as dt
import getBitcoinAddressDetails as gBTC
import json
import sys
import time

ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

def check_result (val, func, args):
    if val == 0: raise ValueError 
    else: return ctypes.c_void_p (val)

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = check_result

class KEY:
    def __init__(self):
        NID_secp256k1 = 714
        self.k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)
        self.compressed = False
        self.POINT_CONVERSION_COMPRESSED = 2
        self.POINT_CONVERSION_UNCOMPRESSED = 4

    def __del__(self):
        if ssl:
            ssl.EC_KEY_free(self.k)
        self.k = None

    def generate(self, secret=None):
        if secret:
            self.prikey = secret
            priv_key = ssl.BN_bin2bn(secret, 32, ssl.BN_new())
            group = ssl.EC_KEY_get0_group(self.k)
            pub_key = ssl.EC_POINT_new(group)
            ctx = ssl.BN_CTX_new()
            ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
            ssl.EC_KEY_set_private_key(self.k, priv_key)
            ssl.EC_KEY_set_public_key(self.k, pub_key)
            ssl.EC_POINT_free(pub_key)
            ssl.BN_CTX_free(ctx)
            return self.k
        else:
            return ssl.EC_KEY_generate_key(self.k)

    def get_pubkey(self):
        size = ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_secret(self):
        bn = ssl.EC_KEY_get0_private_key(self.k);
        bytes = (ssl.BN_num_bits(bn) + 7) / 8
        mb = ctypes.create_string_buffer(bytes)
        n = ssl.BN_bn2bin(bn, mb);
        return mb.raw.rjust(32, chr(0))

    def set_compressed(self, compressed):
        self.compressed = compressed
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        ssl.EC_KEY_set_conv_form(self.k, form)

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(b58_digits[r]))
    return ''.join(l)

def base58_decode(s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_digits.index(ch)
        n += digit
    return n

def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def base58_decode_padded(s):
    pad = 0
    for c in s:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    h = '%x' % base58_decode(s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode('hex')
    return chr(0) * pad + res

def base58_check_encode(s, version=0):
    vs = chr(version) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def base58_check_decode(s, version=0):
    k = base58_decode_padded(s)
    v0, data, check0 = k[0], k[1:-4], k[-4:]
    check1 = dhash(v0 + data)[:4]
    if check0 != check1:
        raise BaseException('checksum error')
    if version != ord(v0):
        raise BaseException('version mismatch')
    return data

def gen_eckey(passphrase=None, secret=None, pkey=None, compressed=False, rounds=1, version=0):
    k = KEY()
    if passphrase:
        secret = passphrase.encode('utf8')
        for i in xrange(rounds):
            secret = hashlib.sha256(secret).digest()
    if pkey:
        secret = base58_check_decode(pkey, 128+version)
        compressed = len(secret) == 33
        secret = secret[0:32]
    k.generate(secret)
    k.set_compressed(compressed)
    return k

def get_addr(k,version=0):
    pubkey = k.get_pubkey()
    secret = k.get_secret()
    hash160 = rhash(pubkey)
    addr = base58_check_encode(hash160,version)
    payload = secret
    if k.compressed:
        payload = secret + chr(1)
    pkey = base58_check_encode(payload, 128+version)
    return addr, pkey

def reencode(pkey,version=0):
    payload = base58_check_decode(pkey,128+version)
    secret = payload[:-1]
    payload = secret + chr(1)
    pkey = base58_check_encode(payload, 128+version)
    print get_addr(gen_eckey(pkey))
    
def addrgen(words = None, input_file = None, output_file = "./results.csv", random = None, show_all_results=False, show_found_results=False, blockchain = False):
    '''
    '''
    results = []

    foundResults = []

    # Opening the output file
    with open(output_file, 'a') as oF:
        if random != None:
            # Creating a random number of bitcoin addresses locally
            for i in range(random):
                # Recovering a random address
                res = get_addr(gen_eckey())
            # Showing the results if requested
            if show_all_results == True:
                print res
            results.append(res)
            # Logging the results into the output file
            oF.write(str(res)+"\n")
        else:
            # In this case, a series of strings may have been provided to generate the addresses
            termsList = []

            # cText is the text to be printed
            cText = term + "\t" + res[0]      
            
            # Command line words...
            if words != None:
                termsList = words
                cText += "\t" + "<TERMINAL>"
            # Lines from a file...
            elif input_file:
                cText += "\t" + input_file
                with open(input_file) as iF:
                    termsList = iF.read().splitlines()
                
            # fText is the text to be stored
            fText = cText       
                
            # Iterating through all the
            for term in termsList:
                res = get_addr(gen_eckey(passphrase=term))

                for r in res:
                    fText += "\t" + r 
                    
                if blockchain:
                    dictInfo = gBTC.getBitcoinAddressDetails(res[0])
                    if dictInfo["n_tx"] > 0:
                        cText += "\t" + "FOUND"
                        fText += "\t" + json.dumps(dictInfo)
                        foundResults.append(cText)
                        # Showing the results if requested
                        if show_found_results == True:
                            print cText
                            results.append(cText)                            
                    else:
                        cText += "\t" + "NOT_FOUND"
                        fText += "\t" + json.dumps({})
                    time.sleep(0.5)
                # Showing the results if requested
                if show_all_results == True:
                    print cText			
                    results.append(fText)
                # Logging the results into the output file
                oF.write(str(fText)+"\n")    

def main(args, otherversion=0):
    ''' 
        Main function.

        :param args:	Arguments recovered from the command line.
        :return: 	An array containing the results.
    '''
    startDate = dt.datetime.now()
    print "Starting date:\t" + str(startDate)
    print "------------------------------------------"

    if not args.input_folder:
        results, foundResults = addrgen(words = args.words, input_file = args.input_file, output_file =args.output_file, random = args.random, show_all_results=args.show_all_results, show_found_results=args.show_found_results, blockchain = args.blockchain)
    else:
        results = []
        foundResults = []
        # Getting file names
        from os import listdir
        from os.path import isfile, join
        onlyfiles = [ f for f in listdir(mypath) if isfile(join(mypath,f)) ]        
        
        # Iterate
        for file in onlyfiles:
            fileResults, fileFoundResults = addrgen(input_file = file, output_file =args.output_file, show_all_results=args.show_all_results, show_found_results=args.show_found_results, blockchain = args.blockchain)
            # Adding to the global results
            results += fileResults
            foundResults += fileFoundResults
    # Storing the end date
    endDate = dt.datetime.now()
    print "------------------------------------------"
    print "End date:\t" + str(endDate)
    
    print
    print "The generation ended successfully." 
    
    print 
    print "The process has taken:\t" + str(endDate-startDate)
    
    print "A total of " + str(len(results)) + " pairs of (<bitcoin_address>, <private_key>) have been created."
    if args.blockchain:
        print "A total of " + str(len(foundResults)) + "  accounts where found in the blockchain."

    return results

    # random compressed
    #print get_addr(gen_eckey(compressed=True,version=otherversion),version=otherversion)
    # uncomment these to create addresses via a different method
    # random uncompressed
    #print get_addr(gen_eckey())
    # by secret
    #print get_addr(gen_eckey(secret=('%064x' % 0xdeadbabe).decode('hex')))
    # by passphrase
    #print get_addr(gen_eckey(passphrase='Satoshi Nakamoto'))
    # by private key
    #print get_addr(gen_eckey(pkey='5K1HkbYffstTZDuV4riUWMbAMkQh57b8798uoy9pXYUDYeUHe7F'))
    #print get_addr(gen_eckey(pkey='L3ATL5R9Exe1ubuAnHVgNgTKZEUKkDvWYAWkLUCyyvzzxRjtgyFe'))

    # uncomment this to reencode the private keys created by early versions of this script
    #reencode(sys.argv[1])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Program to create bitcoin addresses. This software is a fork from the original addrgen.py', prog='i3_addrgen.py', epilog='Check the README.md file for further details on the usage of this program.', add_help=False)
    parser._optionals.title = "Input options (one required)"

    # Defining the mutually exclusive group for the main options
    general = parser.add_mutually_exclusive_group(required=True)
    # Adding the main options
    general.add_argument('--license', required=False, action='store_true', default=False, help='shows the GPLv3 license and exists.')	
    general.add_argument('-f', '--input_file',  metavar='<path_to_terms_file>', action='store', help='path to the file where the list of strings to verify is stored (one per line).')
    general.add_argument('-F', '--input_folder',  metavar='<path_to_dictionary_folder>', action='store', help='path to the folder where the dictionaries are stored.')    
    general.add_argument('-r', '--random', metavar='<random>', action='store', type=int, help = 'generating a random number of addresses.')
    general.add_argument('-w', '--words', metavar='<words>', nargs='+', action='store', help = 'the list of strings to be processed (at least one is required).')

    # Configuring the processing options
    groupProcessing = parser.add_argument_group('Processing arguments', 'Configuring the way in which the program will process the identified addresses.')
    #groupProcessing.add_argument('-o', '--output',  metavar='<path_to_terms_file>', action='store', type=argparse.FileType('a'), help='output folder for the generated documents. While if the paths does not exist, the program will try to create; if this argument is not provided, the ./results folder will be created. Check permissions if something goes wrong.')
    groupProcessing.add_argument('-o', '--output_file', metavar='<path_to_output_file>', required=False, default = './results.csv', action='store', help='output file for the generated documents. Check permissions if something goes wrong.') 
    groupProcessing.add_argument('-T', '--threads', metavar='<num_threads>', required=False, action='store', default=32, type=int, help='write down the number of threads to be used (default 32). If 0, the maximum number possible will be used, which may make the system feel unstable.')
    groupProcessing.add_argument("--blockchain", default=False, action = 'store_true', help="Querying Blockchain for more results. NO control is performed to avoid the restrictions of Blockchain.info API limits.")
    groupProcessing.add_argument("--otherversion", dest="otherversion", default=0, help="Generate address with different version number.")
    

    # Defining the mutually exclusive group for the printing options
    groupShow = parser.add_mutually_exclusive_group(required=False)    
    groupShow.add_argument("--show_all_results", default=False, action = 'store_true', help="Showing the generated results in the terminal. Note that the output will only show if there exists information in the blockchain. It will only print the word, associated bitcoin address and whether there exist information in the blockchain.")
    groupShow.add_argument("--show_found_results", default=False, action = 'store_true', help="Showing the ONLY the found results in the terminal. Note that the output will only show if there exists information in the blockchain. It will only print the word, associated bitcoin address and whether there exist information in the blockchain.")

    # About options
    groupAbout = parser.add_argument_group('About arguments', 'Showing additional information about this program.')
    groupAbout.add_argument('-h', '--help', action='help', help='shows this help and exists.')
    groupAbout.add_argument('--version', action='version', version='%(prog)s v0.3.0', help='shows the version of the program and exists.')

    args = parser.parse_args()	

    # Calling the main function
    main(args)
