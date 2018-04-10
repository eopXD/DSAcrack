from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.PublicKey.pubkey import bignum,inverse
from Crypto.Hash import SHA

from DSAregenK import DSAregenK

import logging
LOG = logging.getLogger('DSAregenK')

def read_file () :
	res = []
	with open("input.txt","r") as file :
		for line in file :
			res.append(line)
	return res

def public_key () :
	'''
	public_key =	y: public exponent
					g: group generator
					p: prime
					q: subprime
	'''
	LOG.info("insert y: ")
	y = input()
	LOG.info("insert g: ")
	g = input()
	LOG.info("insert p: ")
	p = input()
	LOG.info("insert q: ")
	q = input()
	
	return DSA.construct( (y,g,p,q) )
	
def known_message () :
	'''
	mA =	h_m: hash message H(m)
			(r,s): digital signature components
	'''
	LOG.info("insert H(m): ")
	h = input()
	
	LOG.info("insert r: ")
	r = input()
	
	LOG.info("insert s: ")
	s = input()
	
	return h, (r,s)

if __name__ == "__main__" :
	LOG.setLevel(logging.INFO)
	logging.debug("-- on --")
	LOG.info("---- start inserting known message and attributes ----")
#	returns DSA object
	pk = public_key()
#	returns message object
	LOG.info("---- Input -- mA ----")
	mA = known_message()
	LOG.info("---- Input -- mB ----")
	mB = known_message()
	LOG.info("---- input complete ----")

#	organize test data
	data = []
	data.append(mA)
	data.append(mB)

# ============================================================
#
#  Begin ATTACK Code :)
#
# ============================================================
	LOG.debug("---- attack weak coefficient k ----")
	a = DSAregenK(pubkey = pk)
	for h, (r,s) in data :
		a.add( (r,s),h )
	priv_key = ""
	for re_privkey in a.run(asDSAobj = True):
		LOG.info( "Reconstructed private_key: %s | x=%s"%(repr(re_privkey),re_privkey.x))
		priv_key = re_privkey
	LOG.debug("----------------------------------------------------------")
# ============================================================
#
#  Verify attack result by calculating y
#	y = (g ** x) mod p
# ============================================================
	LOG.debug("---- Verify by x ----")
	verify_y = pow(priv_key.g,priv_key.x,priv_key.p)
	LOG.debug("Calculated y: %s"%verify_y)
	LOG.debug("Inserted y: %s"%pk.y)
	if verify_y == pk.y :
		LOG.info("Verified! Successfully reconstructed x!!!")
	else :
		LOG.info("Fail to find real x...QQ")
# ============================================================
#
#  Verify attack result by calculating r,s
#  r = g^k mod p mod q
#  s = k-1 (H(m) + x*r) mod q
# ============================================================
	LOG.debug("---- Verify by r ----")
	k = input("Insert k from output message: ")
	verify_r = pow(priv_key.g,k,priv_key.p) % priv_key.q
	LOG.debug("Calculated r: %s"%verify_r)
	h, (r,s) = mA
	LOG.debug("Inserted   r: %s"%r)
	if verify_r == r :
		LOG.info("Verified! Successfully reconstructed r!!!")
	else :
		LOG.info("Fail to find real r...QQ")

	verify_s = ( inverse(k,priv_key.q) * (h + priv_key.x * verify_r) ) % priv_key.q
	LOG.debug("Calculated s: %s"%verify_s)
	LOG.debug("Inserted   s: %s"%s)
	if verify_s == s :
		LOG.info("Verified! Successfully reconstructed s!!!")
	else :
		LOG.info("Fail to find real s...QQ")
