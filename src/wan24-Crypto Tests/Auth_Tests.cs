using System.Diagnostics;
using System.Text;
using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.Authentication;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Auth_Tests
    {
        [TestMethod, /*Timeout(10000)*/]
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
                serverKeys.SignedPublicCounterKey = new(serverKeys.CounterSignatureKey!.PublicKey);
                serverKeys.SignedPublicCounterKey.Sign(serverKeys.CounterSignatureKey, counterPrivateKey: serverKeys.CounterSignatureKey);
                serverKeys.Public.Signature = serverKeys.SignatureKey.SignData(serverKeys.Public.CreateSignedData());
                CryptoEnvironment.PKI = new();
                CryptoEnvironment.PKI.AddTrustedRoot(serverKeys.SignedPublicKey);
                CryptoEnvironment.PKI.AddTrustedRoot(serverKeys.SignedPublicCounterKey);
                CryptoEnvironment.PKI.EnableLocalPki();
                using PublicKeySuiteStore pks = new();
                using PakeRecordStore prs = new();
                using ServerAuth server = new(new(serverKeys)
                {
                    CryptoOptions = cryptoOptions.GetCopy(),
                    IdentityFactory = (context, ct) =>
                    {
                        Logging.WriteInfo("Identity factory");
                        context.Identity = prs.GetRecord(context.Signup?.Identifier ?? context.Authentication?.Identifier ?? throw new InvalidProgramException("No identifier"));
                        if (context.Identity is not null)
                        {
                            Logging.WriteInfo("Loading public client keys");
                            context.FoundExistingClient = true;
                            // CAUTION: This is NOT a good idea! The PAKE identifier is sentitive data and shouldn't be part of a public object (this is only to simplify the tests)
                            context.PublicClientKeys = pks.GetSuiteByAttribute("PAKE identifier", Convert.ToHexString(context.Identity.Identifier))
                                ?? throw new InvalidProgramException("No public keys");
                        }
                        return Task.CompletedTask;
                    },
                    PayloadHandler = async (context, ct) =>
                    {
                        Logging.WriteInfo("Payload handler");
                        await ServerAuth.ValidateKeySuiteAsync(context, ct);
                        if (context.Signup is not null && context.Payload is not null && context.Payload.IsNewClient && context.Payload.KeySigningRequest is not null)
                        {
                            Logging.WriteInfo("Adding KSR attribute");
                            // CAUTION: This is NOT a good idea! The PAKE identifier is sentitive data and shouldn't be part of a public object (this is only to simplify the tests)
                            context.Payload.KeySigningRequest.Attributes["PAKE identifier"] = Convert.ToHexString(context.Identity!.Identifier);
                        }
                    },
                    SignupValidator = (context, ct) => ServerAuth.ValidateSignupAsync(context, allowAttributes: true, ct),
                    SignupHandler = async (context, ct) =>
                    {
                        Logging.WriteInfo("Signup handler");
                        await prs.AddRecordAsync(new PakeRecord(context.Identity!));
                        pks.AddSuite(context.PublicClientKeys!.GetCopy());
                        await ServerAuth.UpdatePkiAsync(context, ct);
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
                                    Assert.IsNotNull(context.Identity, "Missing identity");
                                    Assert.IsNotNull(context.PublicKeys, "Missing public keys");
                                    Assert.IsNotNull(context.PublicKeys.SignedPublicKey, "Missing signed public key");
                                }
                                else
                                {
                                    Logging.WriteInfo("Client authenticated");
                                    serverAuthSessionKey = context.SessionKey;
                                    return;
                                }
                        Logging.WriteInfo("Server task ending");
                    }
                    catch (OperationCanceledException)
                    {
                        Logging.WriteInfo("Server cancelled");
                    }
                    catch (Exception ex)
                    {
                        Logging.WriteError("Server exception");
                        Logging.WriteError(ex.ToString());
                        //Debugger.Break();
                        //Assert.IsFalse(true);
                    }
                    finally
                    {
                        Logging.WriteInfo("Server task end");
                    }
                });

                // Run the client
                using PrivateKeySuite clientKeys = PrivateKeySuite.CreateWithCounterAlgorithms();
                using BiDirectionalStream emulatedClientSocket = new(channelB, channelA, leaveOpen: true);
                Logging.WriteInfo("Client tests");
                using AsymmetricPublicKeySigningRequest ksr = new(clientKeys.SignatureKey!.PublicKey);
                ksr.SignRequest(clientKeys.SignatureKey);
                byte[] clientSignupSessionKey = await ClientAuth.SignupAsync(emulatedClientSocket, new(clientKeys, "test".GetBytes(), "test".GetBytes16(), new byte[] { 1, 2, 3 })
                    {
                        CryptoOptions = cryptoOptions,
                        PublicKeySigningRequest = ksr,
                        ServerKeyValidator = ClientAuth.ValidateServerPublicKeySuiteAsync
                    }),
                    clientAuthSessionKey = await ClientAuth.AuthenticateAsync(emulatedClientSocket, new(clientKeys, "test".GetBytes(), "test".GetBytes16())
                    {
                        CryptoOptions = cryptoOptions,
                        ServerKeyValidator = ClientAuth.ValidateServerPublicKeySuiteAsync
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
                    Logging.WriteInfo("Waiting for server");
                    await serverTask;
                    Logging.WriteInfo("Server task returned");
                }
                catch (Exception ex)
                {
                    Logging.WriteInfo("Server task exception");
                    Logging.WriteError(ex.ToString());
                }
                Logging.WriteInfo("Server stopped");
            }
            finally
            {
                Logging.WriteInfo("End auth tests");
                if (CryptoEnvironment.PKI is not null)
                {
                    CryptoEnvironment.PKI.Dispose();
                    CryptoEnvironment.PKI = null;
                }
                EncryptionHelper.Algorithms.TryRemove(EncryptionDummyAlgorithm.ALGORITHM_NAME, out _);
            }
        }
    }
}
