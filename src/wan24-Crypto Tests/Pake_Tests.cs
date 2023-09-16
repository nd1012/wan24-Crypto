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
            using FastPakeAuthClient fastClient = new(new SymmetricKeySuite(
                "login_username".GetBytes(),
                RandomNumberGenerator.GetBytes(16)
                ));

            // Server
            using Pake pake = new();
            pake.HandleSignup(fastClient.Pake.CreateSignup());// Ensure having an identity record for the tests
            Assert.IsTrue(pake.HasSession);
            Assert.IsTrue(pake.SessionKey.SequenceEqual(fastClient.SessionKey));
            byte[] signupSessionKey = pake.SessionKey.CloneArray();
            pake.ClearSessionKey();
            fastClient.ClearSessionKey();

            // Fast server
            DateTime start = DateTime.Now;
            using FastPakeAuthServer fastServer = new(pake, fastClient.CreateAuth());
            TimeSpan initTime = DateTime.Now - start;
            Logging.WriteInfo($"Initialization: {initTime}");
            Assert.IsTrue(fastServer.HasSession);
            Assert.IsTrue(fastServer.SessionKey.SequenceEqual(fastClient.SessionKey));
            Assert.IsFalse(signupSessionKey.SequenceEqual(fastServer.SessionKey));
            byte[] firstSessionKey = fastServer.SessionKey.CloneArray();
            pake.ClearSessionKey();
            fastClient.ClearSessionKey();

            // Followup authentication
            start = DateTime.Now;
            fastServer.HandleAuth(fastClient.CreateAuth());
            TimeSpan nextTime = DateTime.Now - start;
            Logging.WriteInfo($"Authentication: {nextTime}");
            Assert.IsTrue(initTime > nextTime);
            Assert.IsTrue(fastServer.HasSession);
            Assert.IsTrue(fastServer.SessionKey.SequenceEqual(fastClient.SessionKey));
            Assert.IsFalse(firstSessionKey.SequenceEqual(fastServer.SessionKey));
            byte[] secondSessionKey = fastServer.SessionKey.CloneArray();
            pake.ClearSessionKey();
            fastClient.ClearSessionKey();

            // Followup authentication
            start = DateTime.Now;
            fastServer.HandleAuth(fastClient.CreateAuth());
            nextTime = DateTime.Now - start;
            Logging.WriteInfo($"Authentication: {nextTime}");
            Assert.IsTrue(initTime > nextTime);
            Assert.IsTrue(fastServer.HasSession);
            Assert.IsTrue(fastServer.SessionKey.SequenceEqual(fastClient.SessionKey));
            Assert.IsFalse(firstSessionKey.SequenceEqual(secondSessionKey));
        }

        [TestMethod]
        public void FastPake2_Tests()
        {
            // Fast client
            using FastPakeAuthClient fastClient = new(new SymmetricKeySuite(
                "login_username".GetBytes(),
                RandomNumberGenerator.GetBytes(16)
                ));

            // Fast server
            DateTime start = DateTime.Now;
            using FastPakeAuthServer fastServer = new(fastClient.Pake.CreateSignup());
            TimeSpan initTime = DateTime.Now - start;
            Logging.WriteInfo($"Initialization: {initTime}");
            Assert.IsTrue(fastServer.HasSession);
            Assert.IsTrue(fastServer.SessionKey.SequenceEqual(fastClient.SessionKey));
            byte[] firstSessionKey = fastServer.SessionKey.CloneArray();
            fastServer.ClearSessionKey();
            fastClient.ClearSessionKey();

            // Followup authentication
            start = DateTime.Now;
            fastServer.HandleAuth(fastClient.CreateAuth());
            TimeSpan nextTime = DateTime.Now - start;
            Logging.WriteInfo($"Authentication: {nextTime}");
            Assert.IsTrue(initTime > nextTime);
            Assert.IsTrue(fastServer.HasSession);
            Assert.IsTrue(fastServer.SessionKey.SequenceEqual(fastClient.SessionKey));
            Assert.IsFalse(firstSessionKey.SequenceEqual(fastServer.SessionKey));
            byte[] secondSessionKey = fastServer.SessionKey.CloneArray();
            fastServer.ClearSessionKey();
            fastClient.ClearSessionKey();

            // Followup authentication
            start = DateTime.Now;
            fastServer.HandleAuth(fastClient.CreateAuth());
            nextTime = DateTime.Now - start;
            Logging.WriteInfo($"Authentication: {nextTime}");
            Assert.IsTrue(initTime > nextTime);
            Assert.IsTrue(fastServer.HasSession);
            Assert.IsTrue(fastServer.SessionKey.SequenceEqual(fastClient.SessionKey));
            Assert.IsFalse(firstSessionKey.SequenceEqual(secondSessionKey));
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
