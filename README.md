Crack DSA 
=========

This repo is forked and added interface from [DSAregenK](https://github.com/tintinweb/DSAregenK)

Recover the private key of signed DSA messages with weak coefficient 'k'. 
The coefficient is considered weak if 'k' is 
* not unique per message
* not randomly selected for signed messages
* small enough to make brute_force feasable


DSA Signature (r,s):

	r = g^k mod p mod q
	s = k-1 (H(m) + x*r) mod q
	
	x 	... private exponent
	y	... public exponent
	H()	... hash function
	m	... message
	g	... group generator
	p	... prime
	q	... subprime
	r,s	... digital signature components
	k	... per message secret number
	

Modus - 'k' is not unique for all signed messages
--------

Given two+ signed message hashes h(mA),h(mB) with signatures (rA,sA) and (rB,sB) where rA==rB and shared public_key 
coefficients (at least subprime q) one can reconstruct the private key used to sign these messages.

DSAregenK().run() - will try to find duplicate 'r' and reconstruct the private_key. just feed as many (sig),hash tuples as you want ( .add())

Code: (use run() or _attack())

	a = DSAregenK(pubkey=pubkey)           # feed pubkey 
	a.add( (r1,s1),h1 )                    # add signed messages
	    
	for re_privkey in a.run(asDSAobj=True):     # reconstruct privatekey from samples (needs at least 2 signed messages with equal r param)
	    if re_privkey.x == privkey.x:           # compare regenerated privkey with one of the original ones (just a quick check :))
	        LOG.info( "Successfully bruteforced private_key: %s"%repr(re_privkey))
	    else:
	        LOG.error("Something went wrong :( %s"%repr(re_privkey))

Prerequesites:
=============

In order to reconstruct the private_key of signed DSA messages you need to have:

* public_key parameters q [,y,g,p]
* a signed message consisting of: 
  * h(m) ... hashed message 
  * (r,s)... signature
* [modus #1] at least two messages with equal 'r'
* [modus #2] at least one message with weak 'k' (small value or within a smaller range since we're bruteforcing 'k')


Crack DSA
=========
Simply run the python script and follow the instructions. Be careful that what you inserted is already `H(m)`.

```
python DSAcrack.py
```

See debug messages by setting `level = logging.DEBUG`

## Sample Input

```
INFO:DSAregenK:---- start inserting known message and attributes ----
INFO:DSAregenK:insert y:
13687856048078264228233274490732090874174262344932880974431687343290054858131451684308666395948030427622295810016000101862173173090875469132553047487280769760636416821339023395895689178976131943591267107929273974777097556182963723283628250281138736044665158182820677338303108870830646721442508547287856230573
INFO:DSAregenK:insert g:
10555268688618437610938814510411577490266949046432207683796678998728574600141816302944970631186552570349829999563883921130078742946264243530963518318919467406091627406799564898505725478186351550540977239893769715697729824607261666854268073417642675596310134833179127942389022184722028782970381454590427584906
INFO:DSAregenK:insert p:
89884656743115888541311565026391917630569252437729993916061135150228586413941047528533882315749744725084874572738901616422782367668406752312375589980020669444017929501290416449375258632721558947577215658086327077344634014950572826490934014965339108377693207046077868085763495128412319529500453571936702838699
INFO:DSAregenK:insert q:
1188626858566606964329505936868556496577980545021
INFO:DSAregenK:---- Input -- mA ----
INFO:DSAregenK:insert H(m):
857395097640348327305744475401170640455782257516
INFO:DSAregenK:insert r:
1099295673931121456611160590606195997247849278661
INFO:DSAregenK:insert s:
507481308197831788681546632880957746745409354771
INFO:DSAregenK:---- Input -- mB ----
INFO:DSAregenK:insert H(m):
199515072252589500574227853970213073102209507294
INFO:DSAregenK:insert r:
1099295673931121456611160590606195997247849278661
INFO:DSAregenK:insert s:
264509052788952870094113710373011978830945136869
INFO:DSAregenK:---- input complete ----
```

## Sample Output

```
INFO:DSAregenK:privkey reconstructed: k=876128291455291996529808560435459570750081675032; x=384160046737431547253603743136647350659834291028;
INFO:DSAregenK:Reconstructed private_key: <_DSAobj @0x1013554d0 y,g,p(1024),q,x,private> | x=384160046737431547253603743136647350659834291028
INFO:DSAregenK:Verified! Successfully reconstructed x!!!
Insert k from output message: 876128291455291996529808560435459570750081675032
INFO:DSAregenK:Verified! Successfully reconstructed r!!!
INFO:DSAregenK:Verified! Successfully reconstructed s!!!
```

Dependencies:
=============

* [PyCrypto](https://www.dlitz.net/software/pycrypto/)


More Infos:
===========

* [DSA requirements for random k values](http://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/)


