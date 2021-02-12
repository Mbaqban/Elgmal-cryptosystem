from primality import get_random_prime
from random import choice


class Elgamal():
    def __init__(self, bites):
        self.bites = bites

    def fast_power(self, a, e, n):
        accum = 1
        while e:
            while not (e % 2):
                e //= 2
                a = ((a % n)**2) % n
            e -= 1
            accum = ((a % n)*(accum % n)) % n
        return accum

    def get_alpha(self, number):
        for i in range(1, number):
            r = []
            for j in range(1, number):
                r.append(self.fast_power(i, j, number))
            r.sort()
            if r == [*range(1, number)]:
                return i
        return 0

    def make_keys(self):
        # Select a large random prime p
        p = get_random_prime(self.bites)

        # Select a generator alfa of the multiplicative group GF(p) of the integers modulo p.
        alpha = self.get_alpha(p)

        # Select a random integer a, 0<a<p-1
        a = choice([*range(0, p)])

        # Compute alpha**a mod p.
        c = self.fast_power(alpha, a, p)

        # The public key is (p, alpha,alpha**a)
        # The private key is a.
        self.__keys = {
            "pub_key": {
                "p": p,
                "alpha": alpha,
                "c": c
            },
            "pv_key": {
                "a": a,
            }
        }

    # Encryption. sender should do the following:
    # 1.    Obtain receiver’s authentic public key (p, alpha,alpha**a).
    # 2.    Represent the message as an integer m in the range (0, 1, . . . , p - 1).
    # 3.    Select a random integer k, 0<k<p-1.
    # 4.    Compute gama = alpha**k mod p and teta=message * (alpha**a)**k mod p.
    # 5.    Send the ciphertext = (gama,teta) to receiver.
    def encrypt(self, message):

        p = self.__keys['pub_key']["p"]
        alpha = self.__keys['pub_key']["alpha"]
        c = self.__keys['pub_key']["c"]
        k = choice([*range(0, p)])

        if message > p-1:
            print(f"\nerror : message must be smaller than {p-1}\n")
            return None

        return {
            "gama": self.fast_power(alpha, k, p),
            "teta": (message * (self.fast_power(c, k, p))) % p
        }

    # Decryption. To recover plaintext m from c, A should do the following:
    # 1.    Use the private key a to compute gama**(p-1-a) mod p.
    # 2.    Recover message by computing (gama**(p-1-a)) * teta mod p.
    def decrypt(self, cypher_text):
        p = self.__keys['pub_key']["p"]
        a = self.__keys['pv_key']["a"]

        gama = cypher_text["gama"]
        teta = cypher_text["teta"]

        return (self.fast_power(gama, p-1-a, p) * teta) % p
