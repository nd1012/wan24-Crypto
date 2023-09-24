using System.Security.Cryptography;
using System.Text;
using wan24.Core;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Pake_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            // PAKE initialization
            using Pake client = new(new SymmetricKeySuite(// Client may be a web-browser
                "login_username".GetBytes(), // Login username
                RandomNumberGenerator.GetBytes(16) // Login password
                ));
            using Pake server = new();// Server may be a web app backend

            // Signup the client at the server
            server.HandleSignup(client.CreateSignup());// The result of CreateSignup needs to be sent to the server using a wrapping PFS protocol (and be disposed)!
            Assert.IsTrue(client.SessionKey.SequenceEqual(server.SessionKey));// Session key was exchanged
            Assert.IsNotNull(server.Identity);// Identity signup data should be stored in the DBMS to perform a login later

            // Destroy the signup session before the authentication test
            Array.Clear(client.SessionKey);// client.ClearSessionKey() or disposing in real life
            Array.Clear(server.SessionKey);// server.ClearSessionKey() or disposing in real life
            server.SessionKey[0] = 1;// Only for testing new session key creation!

            // Authenticate the client at the server
            server.HandleAuth(client.CreateAuth());// The result of CreateAuth needs to be sent to the server using a wrapping PFS protocol (and be disposed)!
            Assert.IsTrue(client.SessionKey.SequenceEqual(server.SessionKey));// Session key was exchanged
        }

        [TestMethod]
        public void FastPake_Tests()
        {
            // Fast client
            DateTime start = DateTime.Now;
            using FastPakeAuthClient fastClient = new(
                new(new SymmetricKeySuite(
                    "login_username".GetBytes(),
                    RandomNumberGenerator.GetBytes(16)
                )), 
                out PakeSignup signup, 
                out byte[] clientSignupSessionKey
                );
            TimeSpan clientInitTime = DateTime.Now - start;
            Logging.WriteInfo($"Client Initialization: {clientInitTime}");

            // Fast server
            start = DateTime.Now;
            using FastPakeAuthServer fastServer = new(signup);
            TimeSpan serverInitTime = DateTime.Now - start;
            Logging.WriteInfo($"Server initialization: {serverInitTime}");
            Assert.IsTrue(fastServer.Pake.HasSession);
            Assert.IsTrue(fastServer.Pake.SessionKey.SequenceEqual(clientSignupSessionKey));
            fastServer.Pake.ClearSessionKey();

            // Followup authentication
            start = DateTime.Now;
            (PakeAuth auth1, byte[] clientSessionKey1) = fastClient.CreateAuth();
            TimeSpan clientAuthTime = DateTime.Now - start;
            Logging.WriteInfo($"Client authentication 1: {clientAuthTime}");
            Assert.IsTrue(clientInitTime > clientAuthTime);
            Assert.IsFalse(clientSignupSessionKey.SequenceEqual(clientSessionKey1));
            start = DateTime.Now;
            (_, byte[] serverSessionKey1) = fastServer.HandleAuth(auth1);
            TimeSpan serverAuthTime = DateTime.Now - start;
            Logging.WriteInfo($"Server authentication 1: {clientAuthTime}");
            Assert.IsTrue(serverInitTime > serverAuthTime);
            Assert.IsTrue(clientSessionKey1.SequenceEqual(serverSessionKey1));

            // Followup authentication
            start = DateTime.Now;
            (PakeAuth auth2, byte[] clientSessionKey2) = fastClient.CreateAuth();
            clientAuthTime = DateTime.Now - start;
            Logging.WriteInfo($"Client authentication 2: {clientAuthTime}");
            Assert.IsTrue(clientInitTime > clientAuthTime);
            Assert.IsFalse(clientSignupSessionKey.SequenceEqual(clientSessionKey2));
            Assert.IsFalse(clientSessionKey2.SequenceEqual(clientSessionKey1));
            start = DateTime.Now;
            (_, byte[] serverSessionKey2) = fastServer.HandleAuth(auth2);
            serverAuthTime = DateTime.Now - start;
            Logging.WriteInfo($"Server authentication 2: {clientAuthTime}");
            Assert.IsTrue(serverInitTime > serverAuthTime);
            Assert.IsTrue(clientSessionKey2.SequenceEqual(serverSessionKey2));
            Assert.IsFalse(clientSessionKey1.SequenceEqual(clientSessionKey2));
            Assert.IsFalse(serverSessionKey1.SequenceEqual(serverSessionKey2));
        }

        [TestMethod]
        public void EncryptedPayload_Tests()
        {
            // PAKE initialization
            using Pake client = new(new SymmetricKeySuite(
                "login_username".GetBytes(),
                RandomNumberGenerator.GetBytes(16)
                ));
            using Pake server = new();

            // Signup the client at the server
            server.HandleSignup(client.CreateSignup());
            Assert.IsTrue(client.SessionKey.SequenceEqual(server.SessionKey));
            Assert.IsNotNull(server.Identity);
            client.ClearSessionKey();
            server.ClearSessionKey();

            // Authenticate the client at the server
            byte[] payload = "test".GetBytes();
            using PakeAuth auth = client.CreateAuth(payload.CloneArray(), encryptPayload: true);
            Assert.IsTrue(payload.Length < auth.Payload.Length);
            byte[] decryptedPayload = server.HandleAuth(auth, decryptPayload: true);
            Assert.IsTrue(client.SessionKey.SequenceEqual(server.SessionKey));
            Assert.IsTrue(decryptedPayload.SequenceEqual(payload));
        }
    }
}
