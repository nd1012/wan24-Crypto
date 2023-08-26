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

            // Destroy the signup session
            Array.Clear(client.SessionKey);// client.ClearSessionKey() or disposing in real life
            Array.Clear(server.SessionKey);// server.ClearSessionKey() or disposing in real life
            server.SessionKey[0] = 1;// Only for testing new session key creation!

            // Authenticate the client at the server
            server.HandleAuth(client.CreateAuth());// The result of CreateAuth needs to be sent to the server using a wrapping PFS protocol (and be disposed)!
            Assert.IsTrue(client.SessionKey.SequenceEqual(server.SessionKey));// Session key was exchanged
        }
    }
}
