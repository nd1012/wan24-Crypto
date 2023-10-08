using System.Collections.Concurrent;
using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.Authentication;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class PakeAuth_Tests
    {
        [TestMethod, Timeout(10000)]
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
                ConcurrentDictionary<byte[], (IPakeRecord Client, IPakeAuthRecord Server)> db = new();
                using PakeServerAuth server = new(new()
                {
                    CryptoOptions = cryptoOptions.GetCopy(),
                    ClientAuthFactory = (context, identifier, ct) =>
                    {
                        byte[] id = identifier.ToArray();
                        Logging.WriteInfo($"Client auth factory {Convert.ToHexString(id)}");
                        var kvp = db.FirstOrDefault(kvp => kvp.Key.SequenceEqual(id));
                        if (kvp.Equals(default)) return Task.CompletedTask;
                        context.ClientIdentity = new PakeRecord(kvp.Value.Client);
                        context.ServerIdentity = new PakeAuthRecord(kvp.Value.Server);
                        return Task.CompletedTask;
                    },
                    SignupHandler = (context, ct) =>
                    {
                        Logging.WriteInfo($"Signup handler {Convert.ToHexString(context.ServerIdentity!.Identifier)}");
                        db[context.ServerIdentity!.Identifier.CloneArray()] = (new PakeRecord(context.ClientIdentity!), new PakeAuthRecord(context.ServerIdentity));
                        return Task.CompletedTask;
                    },
                    SkipSignatureKeyValidation = true
                });
                using BlockingBufferStream channelA = new(bufferSize: Settings.BufferSize);
                using BlockingBufferStream channelB = new(bufferSize: Settings.BufferSize);
                using BiDirectionalStream emulatedServerSocket = new(channelA, channelB);
                using CancellationTokenSource cts = new();
                byte[]? serverSignupSessionKey = null,
                    serverAuthSessionKey = null;
                Task serverTask = Task.Run(async () =>
                {
                    await Task.Yield();
                    try
                    {
                        while (!cts.IsCancellationRequested)
                            using (PakeAuthContext context = await server.AuthenticateAsync(emulatedServerSocket, new byte[] { 1, 2, 3 }, cts.Token))
                                if (context.Record is not null)
                                {
                                    Logging.WriteInfo("Client signed up");
                                    serverSignupSessionKey = context.SessionKey;
                                    Assert.IsNotNull(context.Identity, "Missing identity");
                                    Assert.IsNotNull(context.Record, "Missing record");
                                    Assert.IsNotNull(context.ClientTimeOffset, "Missing time offset");
                                }
                                else
                                {
                                    Logging.WriteInfo("Client authenticated");
                                    serverAuthSessionKey = context.SessionKey;
                                    Assert.IsNotNull(context.Identity, "Missing identity");
                                    Assert.IsNotNull(context.ClientTimeOffset, "Missing time offset");
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
                using SymmetricKeySuite symmetricKey = new(
                    Pake.DefaultOptions,
                    RND.GetBytes(MacHelper.DefaultAlgorithm.MacLength),
                    RND.GetBytes(MacHelper.DefaultAlgorithm.MacLength)
                    );
                using BiDirectionalStream emulatedClientSocket = new(channelB, channelA, leaveOpen: true);
                IPakeAuthRecord serverIdentity;
                Logging.WriteInfo("Client signup");
                DateTime started = DateTime.Now;
                using (PakeAuthContext context = await emulatedClientSocket.SignupAsync(new PakeClientAuthOptions(symmetricKey, new byte[] { 1, 2, 3 })
                {
                    CryptoOptions = cryptoOptions.GetCopy()
                }))
                {
                    Assert.IsNotNull(context.Record);
                    serverIdentity = new PakeAuthRecord(context.Record);
                    await Task.Delay(200);// Let the server work on the context, first
                    Assert.IsNotNull(serverSignupSessionKey);
                    Assert.IsTrue(serverSignupSessionKey.SequenceEqual(context.SessionKey.Value));
                };
                Logging.WriteInfo($"Client runtime {DateTime.Now - started}");
                Logging.WriteInfo("Client authentication");
                started = DateTime.Now;
                using (PakeAuthContext context = await emulatedClientSocket.AuthenticateAsync(new PakeClientAuthOptions(symmetricKey, serverIdentity)
                {
                    CryptoOptions = cryptoOptions.GetCopy()
                }))
                {
                    Assert.IsNull(context.Record);
                    await Task.Delay(200);// Let the server work on the context, first
                    Assert.IsNotNull(serverAuthSessionKey);
                    Assert.IsTrue(serverAuthSessionKey.SequenceEqual(context.SessionKey.Value));
                };
                Logging.WriteInfo($"Client runtime {DateTime.Now - started}");// Runs very fast when setting a FastPakeClientAuth instance to a context

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
                EncryptionHelper.Algorithms.TryRemove(EncryptionDummyAlgorithm.ALGORITHM_NAME, out _);
            }
        }
    }
}
