# Elgmal-cryptosystem
implementation of elgamal algorithm in python


## Installation

its script dont need installation

## Usage

```python
elgamal_system = Elgamal(bites=10)
elgamal_system.make_keys()
char = "a"
char_to_int = ord(char)

c = elgamal_system.encrypt(message=char_to_int)

m = elgamal_system.decrypt(cypher_text=c)

print(chr(m))
```

bites is size of prime numbers that algorithm use.
posetive integer number   4 <= bites <= 10
