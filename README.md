# SHA, HMAC, PBKDF2

A python + tkinter application of the SHA, HMAC and PBKDF2 algorithms.

## The background

- SHA (Secure Hashing Algorithm): SHA is a family of cryptographic hash functions that transform input data into a fixed-size hash value, which is a string of numbers. It’s used for hashing data and certificates. The SHA family includes different versions such as SHA-1, SHA-2, and SHA-3. SHA-1 was the original secure hashing algorithm, returning a 160-bit hash digest after hashing. SHA-2 includes versions like SHA-256 and SHA-512, which denote the bit lengths of the SHA-2.
- HMAC (Hash-Based Message Authentication Codes): HMAC is a cryptographic authentication technique that uses a hash function and a secret key. It’s used for both data integrity and authentication. HMAC keys consist of two parts: cryptographic keys and a hash function. HMAC provides client and server with a shared private key that is known only to them.
- PBKDF2 (Password-Based Key Derivation Function 2): PBKDF2 is a key derivation function used to reduce vulnerability to brute-force attacks. It applies a pseudorandom function, such as HMAC, to the input password or passphrase along with a salt value and repeats the process many times to produce a derived key. The added computational work makes password cracking much more difficult, and is known as key stretching.
