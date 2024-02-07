# Fundamental cryptography basics

This document addresses developers which want to understand commonly used, 
basic cryptography terms, and how to use them in which context. It is a 
compressed explaination, a crash course only, which tries to give a short 
overview over what a developer should know for a quick start with 
cryptography.

## Cipher

A cipher is a cryptographic algorithm, which produces cipher data by 
encryption, and reproduces the raw data by decryption. Example algorithms:

- AES
- Serpent
- ChaCha20

### Block vs stream cipher

A block cipher encrypts fixed sized data blocks, while a stream cipher 
encrypts byte per byte. ChaCha20 is a stream cipher, for example, while AES is 
a block cipher.

### CBC vs GCM cipher mode

It's a good practice to validate cipher data before trying to decrypt it. For 
CBC authenticating the cipher data is an additional mandatory step, while GCM 
(AEAD) includes this step by calculating and appending a MAC to the produced 
cipher data.

## Asymmetric vs symmetric

While symmetric algorithms are "one way", asymmetric algorithms are being used 
bi-directional. Symmetric cryptography algorithms use a key sequence which is 
required to decrypt/validate the produced cipher data. Asymmetric cryptography 
algorithms use a private and a public key, where the private key is used to 
sign data or derive a key from a public key, and the public key is used to 
validate a signature or as key exchange data.

A symmetric key is a secret, just as an asymmetric private key. The asymmetric 
public key can be shared and is often used to identify a party, too. Using an 
asymmetric algorithm which supports key exchange, a symmetric key can be 
produced/derived from the own private key by exchanging the public key between 
two peers.

Usually symmetric algorithms are fast and almost impossible to crack, while 
asymmetric algorithms are slower and depend on an unsolved mathematical 
problem. Once the mathematical problem was solved, the asymmetric algorithm is 
broken. However, a brute force attack (trying all possible keys) is always 
possible with any cryptographic method - so "security" is only relative in any 
way.

### EC(C)

Elliptic courves allows smaller (and faster to calculate) asymmetric keys, 
which are as secure as larger non-ECC (Elliptic Courve Cryptography) keys, 
which require more ressources for generation and processing.

Standards organisations have defined several cryptographic secure elliptic 
courves, which are safe to use. Other well known courves are edwards25519 and 
edwards448-Goldilocks, for example.

When using Ed25519/448, the private signature key can be converted to a 
X25519/448 key exchange key.

## Hash

A hash can be seen as a checksum of raw data, where it's impossible to derive 
the raw data from its hash sequence. A digital signature algorithm (DSA) 
produces a hash of the raw data to sign, and then signs the hash (because the 
hash is a smaller byte sequence, which can be processed faster).

A hash gives no security, but in combination with a digital signature it can 
be used to validate that the raw data wasn't manipulated, by simply recreating 
the hash from the received data.

Hash algorithms are symmetric algorithms.

## MAC

A MAC (Message Authentication Code) can be seen as an authenticated checksum 
of raw data, where a symmetric key is being used in combination with a hash 
algorithm (HMAC), for example. The produced byte sequence can only be 
reproduced by someone who knows the used symmetric key. A MAC is like a hash, 
which is protected against manipulation by a symmetric key. It's like a 
symmetric digital signature (for private use, without public validation 
possibility).

MAC algorithms are symmetric algorithms.

## KDF

A Key Derivation Function (KDF) is used to derive key bytes for a cipher from 
a possibly weak secret key. KDF algorithms are symmetric, but slown down to 
make is almost impossible to derive the original secret key from the derived 
key bytes by reverse engineering or brute force. For this the algorithms make 
high CPU and/or memory usage of the system.

KDF should always be applied to user passwords before using them with any 
cipher/MAC algorithm.

## Key Exchange (KE)

A key exchange uses a shared public key portion with a private key portion to 
derive the same secret key on both peers, while a man in the middle, which 
could observe the shared public key portion, isn't able to derive the secret 
key without having any private key portion.

There are asymmetric algorithms (Diffie Hellman, for example), as well as 
symmetric algorithms (PAKE, for example).

### PAKE

A PAKE (Password Authenticated Key Exchange) is a key exchange protocol, which 
uses a symmetric secret key for deriving a shared secret. The initiator of a 
key exchange uses his private key exchange information with his secret key and 
a random byte sequence to derive the shared secret key, which can then be 
derived by the peer by using their private key exchange information with the 
random byte sequence from the initiator. The private key exchange information 
for the peer must be communicated in advance (signup), which is security 
critical, while the later communicated random byte sequence may be exposed to 
a possible man in the middle, which won't be able to derive the shared secret 
without the private key information of the addressed peer.

## DSA

A Digital Signture Algorithm (DSA) is an asymmetric algorithm, which uses the 
private key to sign data. The produced signature byte sequence can be 
validated using the public key. It ensures that the signed data wasn't 
manipulated, and it also authenticates the signer. Normally the raw data will 
be hashed, so that only the hash is going to be signed/validated, finally. 
This also has the benefit that a signature can be validated without having to 
have the raw data (the hash is enough for that). In short: The signature 
validates the hash, the hash validates the raw data.

## RNG

A Random Number Generator (RNG) is the base for cryptographic key generation. 
The produced random data must be unpredictable in order to be used for this 
purpose. The best known RNGs today are QRNGs, which derive random data from 
quantum physical effects.

There are different types of RNGs:

- PRNG: Pseudo Random Number Generator
- CSRNG: Cryptographic Secure Random Number Generator
- HWRNG: HardWare (Sensors) Random Number Generator
- QRNG: Quantum Random Number Generator

Some RNGs are seedable, which means adding a random seed byte sequence can be 
used to randomize the current internal state of the RNG to gain more entrophy 
for the produced output. Seedable RNGs should be seeded from time to time to 
preserve the unpredictability of the produced random data. A seed may come 
from hardware sensors or other relieable entrophy sources.

## Key size

The size of an asymmetric or a symmetric key is often given in bits. Symmetric 
ciphers often require a fixed key length, which may be ensured using KDF or a 
hash algorithm. Usually a larger key gains more security - but may result in 
slower processing and increased ressource usage.

## Encryption

### Symmetric

A symmetric cipher is usually used to encrypt pre-compressed raw data. 
Compression is being applied to the raw data, because cipher data usually has 
a higher entrophy, which is not so good to compress.

#### Initialization Vector (IV)

A new random IV byte sequence should be used for each encryption process. The 
IV is used to initialize the used cipher engine. Most algorithms define a 
fixed, required IV length.

### Asymmetric

RSA is being used for encryption since a long time now. But since it's slow, 
it's better to use symmetric algorithms instead. Asymmetric key exchange 
algorithms may be used to create single-use-keys for each symmetric encrypted 
message.

## TPM

A Trusted Platform Module (TPM) is a SoC (System on Chip) security hardware, 
which offers to process cryptographic operations independent from the system 
in an isolated environment, using a key which can only be extracted by 
destroying the TPM. It also has registers for storing private keys and uses a 
key hierarchy (X.509 PKI), and it offers HWRNG functionality.

## KEK and DEK

A Key Encryption Key (KEK) is used to encrypt a Data Encryption Key (DEK), 
while a DEK is used to encrypt raw data. A KEK may be an user secret or a 
device key, for example, and should be TPM secured, if possible. A DEK may be 
a random byte sequence, or an asymmetric key.

## AuthN vs AuthZ

An authentication (AuthN) is a prove of an identity, while an authorization 
(AuthZ) is a permission. An authenticated user is authorized to access his 
data, for example.

## PFS

Perfect Forward Secrecy (PFS) describes a secure communication channel 
establishing and running practice where the used symmetric cipher key is being 
exchanged using an asymmetric key pair which is never being stored anywhere 
and destroyed right after a peer derived the shared secret. The shared secret 
must be refreshed in an interval during the communication channel is in use. 
The handshake during the communication channel establishment uses pre-shared 
long term asymmetric keys, which are used to authenticate (sign) the key 
exchange pair for deriving the shared secret (PFS session key).

## Post quantum

Quantum computers can be used to solve all mathematical problems of commonly 
used asymmetric algorithms. For medium and long term security post-quantum-
safe ciphers, which are designed to be unbreakable by a quantum computer, 
should be used from today. Since governments tend to store communication now 
and decrypt it later, also for short term security (with a medium or long 
term sight) a PQC (Post Quantum Cryptography) algorithm should be used for 
key exchange, digital signature and as cipher.

Since symmetric cipher algorithms can gain PQ security by simply increasing 
the key size, algorithms like AES are still safe in the medium and long term, 
if keys >=256 bit are being used.

Asymmetric algorithms like RSA, Diffie Hellman or DSA are not PQ-safe at all.

Shake hashes and all SHA3 family hashes and HMACs are PQ-safe. SHA2 family 
hashes are considered to be PQ-safe from 384+ bit (this may be reconsidered 
after quantum computing develops with the time).

Because PQ-safe asymmetric algorithms are still young, it's a good practice 
to use them to envelop common non-PQC algorithms - for example:

- Key exchange: NTRUEncrypt wraps EC Diffie Hellman (ECDH)
- Signature: CRYSTALS-Dilithium wraps ECDSA

This is also being called "hybrid cryptography" in the post quantum manner.

## OTP

One Time Pad (OTP) is known as THE perfect and unbreakable (except brute 
force) cipher, IF

1. the secret key is exactly as long as the raw data
1. the secret key is true random data
1. the secret key is being used only once

This has some problems in the real life:

- A new key, which is as long as the raw data, must be exchanged for each 
message
- Really true random data is quiet hard to produce (QRNG is a solution)

The main problem is the secret key length and its exchange. Since there is no 
practiable solution in most cases, OTP isn't used often.

One Time Pad has nothing to do with One Time Password (wich is also called 
OTP). A one time password is simply being deleted after being used as a 2nd 
factor, for example.

## 2nd factor

Since an user password can be attacked using brute force at last, an 
authentication should use multiple factors like a one time password which has 
been sent with email or SMS, or is being validated by a third party app. In 
general an OTP should always be sent using a third, independent channel which 
authenticates the user in addition. This may also be biometric data (like a 
fingerprint or a face recognition) or the TPM of the user device. More factors 
increase security - the more factors, the better.

## Misc

### User password storage and validation

1. Let the user enter a password using the frontend
1. Apply KDF (using a hash of the password as salt)
1. Create an HMAC of the password hash using a TPM and the KDF byte sequence 
as secret, if possible
1. Send the resulting byte sequence to the backend
1. Apply KDF again (using a random byte sequence as salt)
1. Create an HMAC using a TPM (if possible) and a static secret
1. Store the resulting byte sequence and the KDF salt

For validating the login simply replace the last step by comparing the 
resulting byte sequence with the stored value. For comparing, use a fixed time 
algorithm to avoid timing attacks.

### App key storage

An app may use several keys, and at last the KEK should be stored partial on a 
remote key storage system. To get the full key from the local and the remote 
part, using a TPM is recommended, if possible. The local key part may be 
stored using OS security capabilities (like the filesystem ACL) and contain 
hardware identifiers like type and serial number of the CPU or the system hard 
disc. Add user environment informations to restrict a key for a specific user.
