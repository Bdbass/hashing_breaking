import hashlib as hb
import binascii, os, random

"""
Ran on Intel(R) Xeon(R) CPU E5645 @ 2.40 GHz
Has 24 processing units, 10 cores

algorithms avaliable on my machine, if you're repeating this experiement try running
print(hb.algorithms_available)
to get the algorithms available on your own machine before running the below code

{'shake_256', 'sha3_384', 'SHA256', 'sha3_512', 'whirlpool', 'dsaWithSHA', 
'DSA', 'sha3_256', 'sha512', 'MD5', 'SHA224', 'DSA-SHA', 'SHA384', 
'RIPEMD160', 'ripemd160', 'md4', 'sha256', 'blake2b', 'mdc2', 'md5', 
'SHA1', 'shake_128', 'sha384', 'ecdsa-with-SHA1', 'MD4', 'sha1', 
'sha3_224', 'SHA', 'dsaEncryption', 'sha224', 'sha', 'SHA512', 
'MDC2', 'blake2s'}
"""

"""
Notes about the salt, salt length can be brute forced because 
common hashing algorithms digest sizes are known, and assuming that 
the user is using a common digest algorithm, the salt = (password - digestLength), 
and it is almost always at the beginning or end of the password, though security could
potentially perform a known permutation function on your salt + password, which could 
really slow down a hackers attempt to decrypt the password 
"""

"""
Notes about rounds, when decrypting here, we make an assumption that the password goes
through 100,000 rounds. This is not something that an attacker would know, they would
need to likely test all rounds between, though they could cheat and test regularly occuring
rounds, like 100,000 += some easy number, as that is what is found in most password documentation
"""

"""
Notes on password security, here we've shown that it is not that difficult to determine known 
passwords, which as we've seen can be millions of passwords. These passwords can be reasonably cracked
with moderate computer power and not too much cryptography knowledge nor coding experience. However,
if your password is simply a set of random characters the time it would take to crack your password would increase
exponentially. Rather than a simple brute force attack, an attacker would have to try every combination of strings,
which could be somewhere near 32^(56) combinations which is the below number of combinations, for passwords up to 32 
characters long, with 56 different characters to choose from, an unrealistic number of combinations for a current 
computer to process
(1942668892225729070919461906823518906642406839052139521251812409738904285205208498176)
"""

"""
Will probably only use something like 5000 rounds so it will be less computationally expensive, and then extrapolate how 
long it would take for 100000 to process
"""

chars = [64, 56, 128, 128,  32, 96, 192]
algorithms = ['SHA256', 'sha224', 'SHA512', 'sha512', 'md5', 'sha384']
rounds = 5000
""" 
parses passwords from a list of username password pairs, from a file
stores results in file_to, should complete this as a preprocessing activity
"""
def getPasswords(file_from, file_to, start, end):
	passwords_only = open(file_to, 'w')
	with open(file_from, 'r') as user_and_pass:
		for i, line in enumerate(user_and_pass):
			if i < start:
				continue
			elif i < end:
				temp = line.split('\t')
				passwords_only.write(temp[1])
			else:
				break


def createHashs(file_from, file_to, hashtype, hmac, start, end,):
	hashs = open(file_to, 'w')
	with open(file_from, 'r') as passwords:
		for i, line in enumerate(passwords):
			if i < start:
				continue
			elif i < end:
				psswrd = line.strip() # remove white space
				hashs.write(hash_password(psswrd, hashtype, hmac) + '\n')
			else:
				break


def createRandomHash(file_from, file_to, start, end):
	r = random.randint(0,6)
	if (r == 6):
		hmac = True
		hashtype = ''
	else:
		hashtype = algorithms[r]
		hmac = False
	createHashs(file_from, file_to, hashtype, hmac, start, end)


def hash_password(password, hashtype, hmac):
	if hmac:
		return hmac_password(password)
	elif hashtype in algorithms:
		h = hb.new(hashtype)
		h.update(password.encode('utf-8'))
		return h.hexdigest()
	else:
		print('Invalid hashtype')
		return None


def hash_verify(real_password, guessed_password, hashtype, hmac):
	if hmac:
		return hmac_verify(password, guessed_password)
	elif (hashtype in algorithms):
		h = hb.new(hashtype)
		h.update(guessed_password.encode('utf-8'))
		return real_password == h.hexdigest()
	else:
		print('Invalid hashtype')
		return None


def hmac_password(password):
	#hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None)¶
	# salt is hashed since it needs to be a consistent size every time
	# os.urandom(60) produces a random byte string up to 60 bytes long
    salt = hb.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash =  binascii.hexlify(hb.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, rounds))
    return (salt + pwdhash).decode('ascii')


def hmac_verify(real_password, guessed_password):
	#hash of sha256 is 64 characters long
    salt = real_password[:64]
    real_password = real_password[64:]
    pwdhash = binascii.hexlify(hb.pbkdf2_hmac('sha512', 
                                  guessed_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  rounds)).decode('ascii')
    print('guessed pwd: '+ pwdhash)
    return pwdhash == real_password


def checkBits(file):
	with open(file, 'r') as passwords:
		line = passwords.readline()
		line = line.strip()
		return len(line.encode('utf-8')) 


def determineAlgorithm(file):
	index = chars.index(checkBits(file))
	if index < 6:
		return algorithms[index], False
	else:
		return '', True	


def createDictionary(file):
	hash_dict = {}
	with open(file, 'r') as hash_file:
		for i, line in enumerate(hash_file):
			line = line.strip()
			if line in hash_dict:
				hash_dict[line].append(i)
			else:
				hash_dict[line] = [i]
	return hash_dict


def crackFile(common, hashed):
	hash_type, hmac = determineAlgorithm(hashed)
	if hmac:
		print('hash type is hmac')
		crackHMAC(common, hashed)
	else:
		print('hash type is ', hash_type)
		return crackNHMAC(common, hashed, hash_type)

def createSaltDictionary(file):
	hash_dict = {}
	with open(file, 'r') as hash_file:
		for i, line in enumerate(hash_file):
			line = line.strip()
			hash_dict[line[64:]] = i #remove salt 
	return hash_dict


# potential speeds ups, use a GPU (maybe up to 100x times speed up)
# delete hashes that have been cracked, decreasing inner loop size
def crackHMAC(common, hashed):
	hash_dict = createSaltDictionary(hashed)
	count = 0
	with open(common, 'r') as common_passwords:
		for i, common_pass in enumerate(common_passwords):
			if i < 500: # try going through first 500 passwords
				common_pass = common_pass.strip()
				with open(hashed, 'r') as hashed_passwords:
					for j, hash_pass in enumerate(hashed_passwords):
						if j < 1000: # try going first 1000 salts
							salt = hash_pass.strip()
							salt = salt[:64]
							temp_hash = binascii.hexlify(hb.pbkdf2_hmac('sha512', common_pass.encode('utf-8'), 
		                                salt.encode('ascii'), rounds)).decode('ascii')
							if temp_hash in hash_dict:
								count += 1
						else: 
							break
			else: 
				break
	return count


def crackNHMAC(common_pass_file, hashed_pass_file, hashtype):
	hash_dict = createDictionary(hashed_pass_file)
	count = 0
	with open(common_pass_file, 'r') as common_passwords:
		for line in common_passwords:
			line = line.strip()
			temp_hash = hash_password(line, hashtype, False)
			if temp_hash in hash_dict:
				count += len(hash_dict[temp_hash])
	return count


def main():
	# createRandomHash('half_million_passwords.txt', 'hash_test.txt', 0, 10000)
	# print('Passwords hashed')
	print(crackFile('rockyou.txt', 'hash_test.txt'))

main()

