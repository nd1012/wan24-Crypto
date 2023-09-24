using System.Diagnostics;
using System.Text;
using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.Networking;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Auth_Tests
    {
        [TestMethod, /*Timeout(3000)*/]
        public async Task GeneralAsync_Tests()
        {
            try
            {
                // Options for encryption
                EncryptionHelper.Algorithms[EncryptionDummyAlgorithm.ALGORITHM_NAME] = EncryptionDummyAlgorithm.Instance;
                CryptoOptions cryptoOptions = new CryptoOptions()
                    .WithEncryptionAlgorithm(EncryptionDummyAlgorithm.ALGORITHM_NAME)
                    .WithoutCompression()
                    .WithoutMac()
                    .WithoutKdf()
                    .IncludeNothing()
                    .WithoutRequirements(CryptoFlags.FLAGS);

                // Run the server
                using PrivateKeySuite serverKeys = PrivateKeySuite.CreateWithCounterAlgorithms();
                serverKeys.SignedPublicKey = new(serverKeys.SignatureKey!.PublicKey);
                serverKeys.SignedPublicKey.Sign(serverKeys.SignatureKey, counterPrivateKey: serverKeys.CounterSignatureKey);
                IPakeRecord? identity = null;
                PublicKeySuite? publicClientKeys = null;
                using ServerAuth server = new(new(serverKeys)
                {
                    CryptoOptions = cryptoOptions.Clone(),
                    IdentityFactory = (context, ct) =>
                    {
                        Logging.WriteInfo("Identity factory");
                        if (identity is not null)
                        {
                            Logging.WriteInfo("Loading identity");
                            if (context.Authentication is not null) Assert.IsTrue(identity.Identifier.SequenceEqual(context.Authentication.Identifier));
                            context.Identity = identity;
                            context.PublicClientKeys = publicClientKeys;
                        }
                        return Task.CompletedTask;
                    }
                });
                using BlockingBufferStream channelA = new(bufferSize: Settings.BufferSize);
                using BlockingBufferStream channelB = new(bufferSize: Settings.BufferSize);
                using BiDirectionalStream emulatedServerSocket = new(channelA, channelB);
                using CancellationTokenSource cts = new();
                byte[]? serverSignupSessionKey = null,
                    serverAuthSessionKey = null;
                Task serverTask = Task.Run(async () =>
                {
                    try
                    {
                        while (!cts.IsCancellationRequested)
                            using (ClientAuthContext context = await server.AuthenticateAsync(emulatedServerSocket, new byte[] { 1, 2, 3 }, cts.Token))
                                if (context.IsNewClient)
                                {
                                    Logging.WriteInfo("Client signed up");
                                    serverSignupSessionKey = context.SessionKey;
                                    Assert.IsNotNull(context.Identity);
                                    identity = context.Identity;
                                    Assert.IsNotNull(context.PublicKeys);
                                    Assert.IsNotNull(context.PublicKeys.SignedPublicKey);
                                    publicClientKeys = context.PublicKeys;
                                }
                                else
                                {
                                    Logging.WriteInfo("Client authenticated");
                                    serverAuthSessionKey = context.SessionKey;
                                    Assert.AreEqual(identity, context.Identity);
                                    Assert.AreEqual(publicClientKeys, context.PublicKeys);
                                }
                    }
                    catch (OperationCanceledException)
                    {
                        Logging.WriteInfo("Server cancelled");
                    }
                    catch (Exception ex)
                    {
                        Logging.WriteError(ex.ToString());
                        //Debugger.Break();
                        //Assert.IsFalse(true);
                    }
                });

                // Run the client
                using PrivateKeySuite clientKeys = PrivateKeySuite.CreateWithCounterAlgorithms();
                using BiDirectionalStream emulatedClientSocket = new(channelB, channelA, leaveOpen: true);
                Logging.WriteInfo("Client tests");
                byte[] clientSignupSessionKey = await ClientAuth.SignupAsync(emulatedClientSocket, new(clientKeys, "test".GetBytes(), "test".GetBytes16(), new byte[] { 1, 2, 3 })
                {
                    CryptoOptions = cryptoOptions
                }),
                    clientAuthSessionKey = await ClientAuth.AuthenticateAsync(emulatedClientSocket, new(clientKeys, "test".GetBytes(), "test".GetBytes16())
                    {
                        CryptoOptions = cryptoOptions
                    });
                Logging.WriteInfo("Check signed public key");
                Assert.IsNotNull(clientKeys.SignedPublicKey);
                Logging.WriteInfo("Validate signed public key");
                clientKeys.SignedPublicKey.Validate();
                Logging.WriteInfo("Check signup session key");
                Assert.IsNotNull(serverSignupSessionKey);
                Assert.IsTrue(serverSignupSessionKey.SequenceEqual(clientSignupSessionKey));
                Logging.WriteInfo("Check auth session key");
                Assert.IsNotNull(serverAuthSessionKey);
                Assert.IsTrue(serverAuthSessionKey.SequenceEqual(clientAuthSessionKey));

                // Stop the server
                Logging.WriteInfo("Stopping server");
                cts.Cancel();
                try
                {
                    await serverTask;
                }
                catch (Exception ex)
                {
                    Logging.WriteError(ex.ToString());
                }
            }
            finally
            {
                EncryptionHelper.Algorithms.TryRemove(EncryptionDummyAlgorithm.ALGORITHM_NAME, out _);
            }
        }
    }
}
