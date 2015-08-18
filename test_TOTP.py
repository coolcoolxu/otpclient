import hmac
import sha
import binascii
import time
import base64

def long_to_bytes (val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    #width = val.bit_length()
    
    # in HOTP algorithm, we always need 8 byte length result, so don't cut it out 
    width = 64
	
    # unhexlify wants an multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    # if width is zero, we need to deal with it particularly
    if ( width == 0):
        width +=8
    else:
        width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)
    #print '%s\n' % (fmt)
    
    # get the hex result of val using format, here the number of hex digits is always 16
    # prepend zero (0) to the width, to zero-pad the output
    hexresult = fmt % val
    
    # get the byte flow of val from its hex result
    s = binascii.unhexlify(hexresult)
    

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        # turn over string s left and right
        s = s[::-1]
    
    #print "the type of s is %s" % (type(s))
    #print "the length of s in byte is %s" % (len(s))
    #print 's value in hex is :%s\n' % (s.encode('hex'))
    
    return s

def get_hmac_sha1(secret,counter):
    #get the text from counter
    text = long_to_bytes(counter, 'big')
    #print "The text of transferred count is :%s" % (text.encode('hex'))
    
    #compute hmacsha1 value from secret&text
    h = hmac.new(secret,text,sha)
    digest = h.digest()
        
    return digest
    
    
def get_dt_offset(digest):
    #get the offset of dynamic truncation from digest 
    hashlength = len(digest)
    #print "The length of hmac-sha1 is: %d" % (hashlength)
    
    lasthashbyte = digest[hashlength - 1] 
    #print "The last byte of hash is : %s" % (lasthashbyte.encode('hex'))
    
    #get the int value of last byte from hash string
    intval = int(lasthashbyte.encode('hex'),16)
    #print "The int value of last byte is %d" % (intval)
    
    #calculate the offset from the last 4 bits of intval 
    offset = intval & 0xf
    #print "The type of offset is %s and the value is %d" % (type(offset),offset)
    return offset

def get_dt_decimal(offset,digest):
    #get the Dynamic truncation of digest using offset's last 4 byte with first bit
    DTbinary= digest[offset:offset+4]
    print "The Binary of DT in hex with the first bit not cleared is: %s" % (DTbinary.encode('hex'))
    
    #get the intval of DTbinary
    intval = int(DTbinary.encode('hex'),16)
    
    #get rid of the first bit of intval
    DTval = intval &0x7fffffff
    
    return DTval

    
def get_HOTP(secret,counter,codedigits):
    #set the DIGITS_POWER
    DIGITS_POWER = [1,10,100,1000,10000,100000,1000000,10000000,100000000]
    
    #get hmac-sha1 digest from secret&counter
    digest = get_hmac_sha1(secret,counter)
    print "The value of hmac-sha1(secret,counter) in hex is:\n%s" % (binascii.hexlify(digest))
    
    #get the dt offset from digest
    offset = get_dt_offset(digest)
    #print "The type of offset is %s and the value is %d" % (type(offset),offset)
    
    #get the dt decimal value
    DTval = get_dt_decimal(offset,digest)
    #DTval = 645000123(testing value)
    print "The decimal value of Dynamic truncation of digest is: %d" % (DTval)
    
    HOTP = DTval % DIGITS_POWER[codedigits]
    
    #get the hotp string format prepend zero to the width by codedigits
    fmt = "%%0%dd" % (codedigits)
    #print "the fmt is %s" % fmt
    HOTPstr = fmt % HOTP
    
    return HOTPstr
    
def get_time_counter(Time,T0 = 0,Tstep = 30):
    #T0 is the Unix time to start counting time step (default value is 0, the Unix epoch)
    #Tstep is the time step in seconds(default value is 30 seconds)
    #Time is the current time in seconds
    
    #calculate the time counter
    if ( isinstance(Time,int) or isinstance(Time,long) ):
        counter = (Time - T0)/Tstep
        return counter
    else:
        print "Time value is not a integer!"
    
def get_TOTP(secret,Time,codedigits):
    counter = get_time_counter(Time,0,30)
    TOTPstr = get_HOTP(secret,counter,codedigits)
    return TOTPstr
  
def get_decoded_secret(b32encodedsecret):
    decodedsecret = base64.b32decode(b32encodedsecret)
    return decodedsecret
  
#key = "12345678901234567890"
#Times = [59,1111111109,1111111111,1234567890,2000000000,20000000000]    
#for Time in Times:
#    TOTP = get_TOTP(key,Time,8)
#    print "The TOTP value is %s\n" % (TOTP)

b32encodedsecret = "WODJU6A3HI4ELAW6M6XT6GU4YGPJPALEZ33DI7K7PB3VSGBLX5J2B55PGZURLQQB"
secret = get_decoded_secret(b32encodedsecret)
    
#now = int(time.time())
#TOTP = get_TOTP(secret,now,6)
#print "Using secret in hex %s and current time, the totp is %s\n" %(binascii.hexlify(secret),TOTP)

while True:
    now = int(time.time())
    rest = now % 30
    countdown = 30-rest
    if (rest != 0):
        print "!!!!!!!!!!!!!!!!       wait for %d seconds        !!!!!!!!!!" % (countdown)
        time.sleep(1)
        continue
    else:
        TOTP = get_TOTP(secret,now,6)
        print "!!!!!!!!!!!!!!!!       %s        !!!!!!!!!!\n" % (TOTP)
        time.sleep(1)
    
    
    
