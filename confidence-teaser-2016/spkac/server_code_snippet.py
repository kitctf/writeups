
def dataToVerify(der, secret):
  # We can't trust secret sent by browser, user can modify it !
  der[0][1] = pyasn1.type.char.IA5String(secret)
  return pyasn1.codec.der.encoder.encode(der[0])

def cmpMin(a,b):
  minLen = min(len(a),len(b))
  if minLen < 1:
    # empty string ? !
    return False

  for i in range(minLen):
    if a[::-1][i] <> b[::-1][i]:
       return False
  
  return True

def verify(der, secret):
  md5rsa = pow(getSignature(der), 65537, getN(der))
  md5cmp = ''
  while md5rsa:
    md5cmp = chr(md5rsa % 256) + md5cmp
    md5rsa /= 256
  # md5cmp is with padding, so compare only up to hash length
  return cmpMin(md5cmp, md5.new(dataToVerify(der, secret)).digest())

