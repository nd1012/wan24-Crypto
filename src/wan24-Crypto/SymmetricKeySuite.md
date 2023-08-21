# Symmetric key suite

This note explains something about the authentication application shown in the 
tests.

**CAUTION**: This authentication application is **experimental**!

## General

The tests try to simulate a kind of an asymmetric key exchange with symmetric 
cryptographic algorithms. Of course this is insecure! All the communication 
has to be wrapped with a PFS protocol. The symmetric key exchange only adds 
another layer in this process, which tries to eliminate the weaknesses of 
asymmetric cryptography and make the whole thing (WAY) more secure.

During the signup all informations that are required for the symmetric key 
exchange will rely on the security of the wrapping PFS protocol. But once the 
signup was done, every following authentication uses asymmetric AND symmetric 
cryptographic algorithm security.

The exchanged session key could be combined with the PFS session key.

## Authentification components

- `Secret`: A secret value, which needs to be sent with the signup only
- `Identification`: Could be a login username, for example
- `Random`: A random byte sequence used for creating a session key
- `Auth`: An authentication byte sequence
- `Signature`: A signature which proofes the correctness of the previous 
values, and that the client knowns the value of `Secret` (which is important 
for the login process)

**CAUTION**: The tests are missing a time restriction, which makes replay 
attacks possible! This doesn't mean that a time restriction isn't possible - 
it's only missing because it's just an additional security which doesn't 
affect the goal of the tests, but only would add more code. So the tests 
should be seen as **incomplete** and definitly **not ready to use example**
**code**!

## Security thoughts (and the ideas behind)

`Identification` and `Auth` are never stored on persistent memory at the 
client. They're calculated from user input only. The server will store those 
values for permanent, but never get the raw user input. So the security of 
these informations rely on how the user handles them, finally.

`Identification` and `Auth` are the values which are required to be sent for 
every process (signup/login). `Secret` is only required for the signup. That 
means, `Secret` has only to be transferred once.

`Random` ensures to use a random session key. It should be truly random for 
each session!

`Identification` and `Auth` are constant byte sequences. `Identification` is 
required to be stored 1:1 on the server, while the server will only store a 
non-reversible calculated product of `Auth`.

That means, in case an attacker was able to access the servers database, he 
won't be able to calculate the `Auth` value, which is required for a login, 
within a reasonable time.

In case an attacker is able to spy the communication (which should be avoided 
by the used PFS protocol), he wouldn't be able to use the informations, 
because he can't calculate `Secret`, which is used for signing. But the 
`Secret` value is used to create the session key for the following encrypted 
communication.

This eliminates two attack points:

1. The servers database
1. The client/server communication (MiM attack)

Let's assume the server AND the communication was hacked successfully - the 
attacker now has

- `Secret`
- `Identification`
- `Auth`

These informations are not enough to calculate the login username or password, 
but they can be used to create a successful login. Anyway, for this

- the wrapping PFS protocol AND
- the server AND
- the communication channel (a network router, or a permanent server process)

need to be hacked successfully, first. By only hacking one of these parts, the 
attacker isn't able to use any of the stolen information. In case of a server 
hack, users should be required to change their login information for the next 
login.

Another point is the use of KDF: Both, the client and the server, are required 
to perform a KDF operation. But at the server side KDF is only applied after 
the signature was validated successfully. This will lower the possible attack 
frequency and almost eleminate DoS (which is still possible by login 
hammering, which requires the login username and password to be exposed - or 
in case the server AND the client/server communication was hacked 
successfully). On my Intel i7 CPU from 2016 a single login takes about 35ms. 
This means about 28 possible login tries per second, and 2,419,200 login tries 
per day (using one CPU core). 128 byte (1024 bit) are required to be 
determined for a successful brute force attack, which means 2^1024 login 
tries. On my mashine this would take about 
2.0358741198973462389121108651213 E+299 years. This only in case the login 
username and password are being brute forced.

**NOTE**: As login try time I use the time for calculating values only - 
without the network/internet communication delay/latency.

For brute forcing the exchanged authentication data, 192 byte (1536 bit) need 
to be determined, which requires up to 2^1536 SHA-512 HMAC calculations. If, 
for example, a time restriction of 5 minutes was implemented, this should be 
absolutely safe.

## More benefits from a symmetric key exchange

When ignoring the wrapping PFS protocol, no handshake is required, because 
with the informations sent from the client to the server both sides are able 
to calculate a session key. This enables single-directional communication for 
a protocol which doesn't require a response from the peer.

A handshake can be fully eleminated by pre-sharing PFS protocol required keys, 
which are usually asymmetric public keys. This makes it possible to implement 
a stateless UDP protocol, too.

Asymmetric cryptographic algorithms rely on mathematical problems. Once the 
problem can be solved by an attacker (using a quantum computer f.e.), the 
algorithm is broken.
Symmetric cryptography algorithms rely on the time required to perform a brute 
force attack (and the resources (hardware / money) required to perform such an 
attack).

Usually symmetric cryptography is used to encrypt long term stored 
information, because it's assumed that the algorithm won't be broken in the 
long term. Now it's possible to get the same security for short term encrypted 
communication data in combination with a PFS protocol: After a secure signup 
all communicated data after the symmetric key exchange will be as safe as for 
long term storage encrypted data, even the wrapping PFS protocol was broken. 
That means an additional, even harder to break security layer:

1. PFS wrapper
1. Symmetric key exchange

The client will stay fully anonymous at any time, because no raw information 
needs to be communicated or stored. All stored and communicated values won't 
allow reverse engineering of the used raw data to calculate them.

Another benefit is that a user may even choose an already used login username 
for is authentication, because the ID is generated from the raw login username 
and password, which would allow multiple use of the username from different 
users, as long as they use a different password (which is to be expected).

## Usages

The symmetric key exchange hardens an existing PFS protocol and is being used 
for peer authentication.

Other usages may be:

- Automatted user device to server authentication
- Any user to user (peer to peer) authentication and encrypted communication
- Additional security layer for long term stored cipher data (for this no time 
restriction needs to be implemented)
