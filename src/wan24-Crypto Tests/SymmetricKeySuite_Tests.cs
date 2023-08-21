using System.Security.Cryptography;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class SymmetricKeySuite_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            using SymmetricKeySuite suite = new(RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(32));// Private symmetric key
            Client alice = new();
            Server bob = new();

            // Signup
            KeyExchange signup = alice.CreateSignup(suite);// signup needs to be sent to bob, wrapped using a PFS protocol!
            bob.DoSignup(signup);
            Assert.IsTrue(alice.SessionKey.SequenceEqual(bob.SessionKey));

            // Login
            KeyExchange login = alice.CreateSignup(suite);// login needs to be sent to bob, wrapped using a PFS protocol!
            bob.DoLogin(login);
            Assert.IsTrue(alice.SessionKey.SequenceEqual(bob.SessionKey));
        }

        private sealed class Client
        {
            public byte[] SessionKey = null!;

            public KeyExchange CreateSignup(SymmetricKeySuite key)
            {
                KeyExchange signup = new()
                {
                    Identification = key.Identifier!.Value.ToArray(),
                    Random = RandomNumberGenerator.GetBytes(64),
                    Auth = key.Identifier.Value.Mac(key.ExpandedKey)// Create a MAC
                };
                signup.Secret = signup.CreateSecret(key.ExpandedKey);// Required for the signup only
                byte[] signatureKey = signup.CreateSignatureKey();
                signup.Signature = signup.CreateSignature(signatureKey);
                SessionKey = signup.CreateSessionKey(signatureKey);
                return signup;
            }

            public KeyExchange CreateLogin(SymmetricKeySuite key)
            {
                KeyExchange login = new()
                {
                    Identification = key.Identifier!.Value.ToArray(),
                    Random = RandomNumberGenerator.GetBytes(64),
                    Auth = key.Identifier.Value.Mac(key.ExpandedKey)// Create a MAC
                };
                byte[] signatureKey = login.CreateSignatureKey(),
                    secret = login.CreateSecret(key.ExpandedKey);
                login.Signature = login.CreateSignature(signatureKey, secret);
                SessionKey = login.CreateSessionKey(signatureKey, secret);
                return login;
            }
        }

        private sealed class KeyExchange
        {
            public byte[]? Secret = null;
            public byte[] Identification = null!;
            public byte[] Random = null!;
            public byte[] Auth = null!;
            public byte[] Signature = null!;

            // The secret can't be calculated on the server, because the expanded key is a private client value
            public byte[] CreateSecret(byte[] expandedKey) => expandedKey.Mac(Auth);// Create a MAC

            // The "signature" key
            public byte[] CreateSignatureKey() => Auth.Stretch(64, Identification).Stretched;// Apply KDF

            // A "signature" (MAC)
            public byte[] CreateSignature(byte[] signatureKey, byte[]? secret = null)
                => (secret ?? Secret)!.Concat(Identification).Concat(Random).Concat(Auth).ToArray().Mac(signatureKey);// Create a MAC

            // The session key is created using the random byte sequence
            public byte[] CreateSessionKey(byte[] signatureKey, byte[]? secret = null) => Random.Mac(signatureKey.Mac(secret ?? Secret!));// Create a MAC
        }

        private sealed class Server
        {
            private byte[] Identification = null!;
            private byte[] Secret = null!;
            private byte[] Key = null!;
            public byte[] SessionKey = null!;

            public void DoSignup(KeyExchange signup)
            {
                // Store the authentication information
                Secret = signup.Secret!;
                Identification = signup.Identification;
                Key = signup.CreateSignatureKey();
                // Validate the signup signature
                Assert.IsTrue(signup.Signature.SequenceEqual(signup.CreateSignature(Key)));
                // Create the session key
                SessionKey = signup.CreateSessionKey(Key);
            }

            public void DoLogin(KeyExchange login)
            {
                // Validate the ID
                Assert.IsTrue(Identification.SequenceEqual(login.Identification));
                // Validate the login signature
                Assert.IsTrue(login.Signature.SequenceEqual(login.CreateSignature(Key, Secret)));
                // Validate the login authentication
                Assert.IsTrue(Key.SequenceEqual(login.CreateSignatureKey()));
                // Create the session key
                SessionKey = login.CreateSessionKey(Key, Secret);
            }
        }
    }
}
