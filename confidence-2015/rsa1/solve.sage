#!/usr/bin/sage
#!encoding: UTF-8
#
# Solution for the rsa1 challenge of CONFidence CTF 2015.
# Uses Coppersmith's short padding attack and the Franklin-Reiter attack.
#
# See http://www.di.ens.fr/~fouque/ens-rennes/coppersmith.pdf
# and https://www.cs.unc.edu/~reiter/papers/1996/Eurocrypt.pdf

# Copyright (c) 2015 Samuel Groß
#

from binascii import unhexlify

def coppersmith_short_pad(c1, c2, n):
    """When provided with two ciphertexts of the same message but with different (short)
    paddings, i.e.
        C1 = (M | r1)^3 = M1^3 and
        C2 = (M | r2)^3 = M2^3),
    this function calculates the difference r2 - r1 of the two (random) paddings used
    during encryption using Coppersmith's method. Afterwards, the Franklin-Reiter
    attack can be applied to recover the plaintext.

    See http://www.di.ens.fr/~fouque/ens-rennes/coppersmith.pdf

    Returns all possible values for the difference in a list.
    """
    # Fixed exponent.
    e = 3

    # Create two polynomial rings and corresponding variables. Sage cannot calculate the resultant
    # in a ring of integers modulo N, so we'll use and integer ring for that, then switch rings afterwards.
    RZmodN.<xm> = PolynomialRing(Zmod(n))
    RZ.<x, y> = PolynomialRing(ZZ)

    # Create the two polynomials g1 and g2. If y = r2 - r1, then g1 and g2 both have the root M1.
    g1 = x**e - c1
    g2 = (x + y)**e - c2

    # Calculate the resultant. The resultant is the product of the differences of the roots of the
    # two polynomials. As seen above, for the case that y = r2 - r1, both polynomials have the same
    # root M1, thus r2 - r1 is a root of the resultant of g1 and g2.
    p = g1.resultant(g2)

    #
    # Now let sage do all the work by calculating small roots of the resultant.
    #

    # We need a univariate polynomial for this. At this point, x should be eliminated though.
    p = p.univariate_polynomial()
    # Change rings. We need the ring of integers modulo N now.
    p = p.change_ring(RZmodN).subs(y = xm)
    # Make sure the polynomial is monic, i.e. the coefficient of x^(p.degree()) is 1.
    p = p.monic()
    # Now let sage to the magic. Try to find all small roots of p using Coppersmith's method.
    return p.small_roots(X=2**(512 // 9), beta=0.5)

def franklin_reiter(c1, c2, n, a=1, b=1):
    """Recovers the plain text message from the two cipher texts knowing
    that they were both encrypted using the exponent 3 and that
    M2 = a * M1 + b.

    See https://www.cs.unc.edu/~reiter/papers/1996/Eurocrypt.pdf

    Returns both plain text messages as a tuple.
    """
    f = b*(c2 + 2*(a**3)*c1 - b**3  ) % n
    g = a*(c2 - a**3*c1     + 2*b**3) % n

    # Calculage f / g: f / g = f * g**(-1) = f * inverse_mod(g, n)
    gi = inverse_mod(g, n)
    m = f * gi % n

    return (m, m+b)

def decode(m):
    """Returns the provided number interpreted as a string."""
    h = hex(m)

    if h.startswith('0x'):
        h = h[2:]

    if len(h) % 2 != 0:
        h = '0' + h

    return unhexlify(h)


def main():
    # Input: Ciphertexts C1, C2, with
    #   C1 = (M | r1)^3 = M1^3
    #   C2 = (M | r2)^3 = M2^3
    N = 740765548979273098467598803958212385151570053921334237430171491357308450305938925395058048571558613364002948004291135518240329572789525487495147870779619379982865011328775565850048248526863374376024296921937798169737860584047065593928295857417452372744936947544816804233701992919611488140593397159150152160920639L
    # flag0
    C1 = 321451913057900142348436621563079153898436032837412854031246697790410602040147332179869901737501439750726664592096795391349241878705910327861241059454661619432324907631836944052325945666694131891489395959762339277410381692975197784562565409741727780043108506458930540459411390110527535022558117942647833465024816L
    # flag1
    C2 = 245544492996888727164841815357590445824184017819212225646984254796592976347385430003123536033004742032759416589790020081404988144261423483934413815011827391460021382138980857256740580080876659438050231270325521568176877577234140954433459361598359898768186238850013895811016147701584167992547871319386741583536303L

    #
    # Step 1: Use the Coppersmith Short Padding attack to recover the difference (r2 - r1)
    # between the two paddings.
    #
    roots = coppersmith_short_pad(C1, C2, N)
    assert(roots)

    # The root can be negative (in which case we get a huge root, since we're still in the ring of integers modulo N),
    # because r2 might be smaller than r1. In this case invert the root and switch C1 and C2.
    #
    # TODO check if we got multiple roots. In that case to Franklin-Reiter for each of them
    # and check if the recovered message encrypts to the ciphertext again.
    # (Or just check for ASCII or known words)
    d = roots[0]
    if d >= 2**32:
        C1, C2 = C2, C1
        d = -d

    #
    # Step 2: Use the Franklin-Reiter Attack to recover the plaintext from the ciphertexts.
    # The Franklin-Reiter Attack is applicable if e = 3 and M2 = a * M1 + b.
    # We know b from step 1, and a = 1.
    #
    m, _ = franklin_reiter(C1, C2, N, b=int(d))

    # Remove the padding. We know its 32 bit long.
    m = m >> 32

    # All done :)
    print(decode(m))

if __name__ == '__main__':
    main()
