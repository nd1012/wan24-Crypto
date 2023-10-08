using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;

namespace wan24.Crypto.Tests
{
    public static class HybridTests
    {
        public static void AllAsymmetricTests()
        {
            List<string> seen = new();
            IAsymmetricAlgorithm algo, counterAlgo;
            int done = 0;
            foreach (string name in AsymmetricHelper.Algorithms.Keys)
                foreach (string counterName in AsymmetricHelper.Algorithms.Keys)
                {
                    if (AsymmetricHelper.Algorithms.Count != 1 && name == counterName) continue;
                    if (seen.Contains($"{name} {counterName}") || seen.Contains($"{counterName} {name}")) continue;
                    seen.Add($"{name} {counterName}");
                    algo = AsymmetricHelper.GetAlgorithm(name);
                    counterAlgo = AsymmetricHelper.GetAlgorithm(counterName);
                    if (algo.CanExchangeKey != counterAlgo.CanExchangeKey && algo.CanSign != counterAlgo.CanSign) continue;
                    foreach (int keySize in algo.AllowedKeySizes)
                        foreach (int counterKeySize in counterAlgo.AllowedKeySizes)
                        {
                            AsymmetricTests(new()
                            {
                                AsymmetricAlgorithm = name,
                                AsymmetricCounterAlgorithm = counterName
                            }, keySize, counterKeySize);
                            done++;
                        }
                }
            Console.WriteLine($"{done} tests done");
        }

        public static void AsymmetricTests(CryptoOptions options, int keySize, int counterKeySize)
        {
            Console.WriteLine($"Hybrid asymmetric tests with {options.AsymmetricAlgorithm} ({keySize}) and counter {options.AsymmetricCounterAlgorithm} ({counterKeySize})");
            Stopwatch sw = Stopwatch.StartNew();
            IAsymmetricAlgorithm algo = AsymmetricHelper.GetAlgorithm(options.AsymmetricAlgorithm!),
                counterAlgo = AsymmetricHelper.GetAlgorithm(options.AsymmetricCounterAlgorithm!);
            if (algo.CanExchangeKey && counterAlgo.CanExchangeKey)
            {
                Console.WriteLine("\tRunning key exchange tests");
                options.AsymmetricKeyBits = keySize;
                using IKeyExchangePrivateKey privateKey = AsymmetricHelper.CreateKeyExchangeKeyPair(options);
                options.AsymmetricAlgorithm = counterAlgo.Name;
                options.AsymmetricKeyBits = counterKeySize;
                using IKeyExchangePrivateKey privateKey2 = AsymmetricHelper.CreateKeyExchangeKeyPair(options);
                options.AsymmetricAlgorithm = algo.Name;
                options.PrivateKey = privateKey;
                options.CounterPrivateKey = privateKey2;
                KeyExchangeDataContainer keyExchangeData = new();
                (options.Password, keyExchangeData.KeyExchangeData) = privateKey.GetKeyExchangeData(options: options);
                HybridAlgorithmHelper.GetKeyExchangeData(keyExchangeData, options);
                Assert.IsNotNull(keyExchangeData.CounterKeyExchangeData);
                byte[] keyExchangeDataBytes = (byte[])keyExchangeData;
                keyExchangeData = (KeyExchangeDataContainer)keyExchangeDataBytes;
                byte[] key1 = options.Password;
                HybridAlgorithmHelper.DeriveKey(keyExchangeData, options);
                Assert.IsTrue(key1.SequenceEqual(options.Password));
            }
            if (algo.CanSign && counterAlgo.CanSign)
            {
                Console.WriteLine("\tRunning signature tests");
                options.AsymmetricKeyBits = keySize;
                using ISignaturePrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair(options);
                options.AsymmetricAlgorithm = options.AsymmetricCounterAlgorithm;
                options.AsymmetricKeyBits = counterKeySize;
                using ISignaturePrivateKey privateKey2 = AsymmetricHelper.CreateSignatureKeyPair(options);
                options.AsymmetricCounterAlgorithm = options.AsymmetricAlgorithm;
                options.AsymmetricAlgorithm = privateKey.Algorithm.Name;
                options.CounterPrivateKey = privateKey2;
                SignatureContainer signature = privateKey.SignData(TestData.Data, "Test", options);
                HybridAlgorithmHelper.Sign(signature, options);
                byte[] signatureBytes = (byte[])signature;
                signature = (SignatureContainer)signatureBytes;
                Assert.AreEqual("Test", signature.Purpose);
                Assert.AreEqual(privateKey2.Algorithm.Name, signature.AsymmetricCounterAlgorithm);
                Assert.IsNotNull(signature.CounterSigner);
                Assert.IsTrue(privateKey2.ID.SequenceEqual(signature.CounterSigner));
                Assert.IsNotNull(signature.CounterSignature);
                Assert.IsNotNull(signature.CounterSignerPublicKeyData);
                using ISignaturePublicKey? publicKey = signature.CounterSignerPublicKey;
                Assert.IsNotNull(publicKey);
                Assert.IsTrue(publicKey.ID.SequenceEqual(privateKey2.ID));
                Assert.IsTrue(signature.ValidateSignedData(TestData.Data, throwOnError: false));
            }
            Console.WriteLine($"\tRuntime {sw.Elapsed}");
        }

        public static void AllMacTests()
        {
            List<string> seen = new();
            int done = 0;
            foreach (string name in MacHelper.Algorithms.Keys)
                foreach (string counterName in MacHelper.Algorithms.Keys)
                {
                    if (MacHelper.Algorithms.Count != 1 && name == counterName) continue;
                    if (seen.Contains($"{name} {counterName}") || seen.Contains($"{counterName} {name}")) continue;
                    seen.Add($"{name} {counterName}");
                    MacTests(new()
                    {
                        MacAlgorithm = name,
                        CounterMacAlgorithm = counterName
                    });
                    done++;
                }
            Console.WriteLine($"{done} tests done");
        }

        public static void MacTests(CryptoOptions options)
        {
            Console.WriteLine($"Hybrid MAC tests with {options.MacAlgorithm} and counter {options.CounterMacAlgorithm}");
            Stopwatch sw = Stopwatch.StartNew();
            byte[] mac = options.Mac = TestData.Data.Mac(TestData.Key, options);
            options.Password = TestData.Key;
            HybridAlgorithmHelper.ComputeMac(options);
            Assert.IsFalse(mac.SequenceEqual(options.Mac));
            Assert.AreEqual(MacHelper.GetAlgorithm(options.CounterMacAlgorithm!).MacLength, options.Mac.Length);
            Console.WriteLine($"\tRuntime {sw.Elapsed}");
        }

        public static void AllKdfTests()
        {
            List<string> seen = new();
            int done = 0;
            foreach (string name in KdfHelper.Algorithms.Keys)
                foreach (string counterName in KdfHelper.Algorithms.Keys)
                {
                    if (KdfHelper.Algorithms.Count != 1 && name == counterName) continue;
                    if (seen.Contains($"{name} {counterName}") || seen.Contains($"{counterName} {name}")) continue;
                    seen.Add($"{name} {counterName}");
                    KdfTests(new()
                    {
                        KdfAlgorithm = name,
                        KdfIterations = KdfHelper.GetAlgorithm(name).DefaultIterations,
                        CounterKdfAlgorithm = counterName,
                        CounterKdfIterations = KdfHelper.GetAlgorithm(counterName).DefaultIterations
                    });
                    done++;
                }
            Console.WriteLine($"{done} tests done");
        }

        public static void KdfTests(CryptoOptions options)
        {
            Console.WriteLine($"Hybrid KDF tests with {options.KdfAlgorithm} and counter {options.CounterKdfAlgorithm}");
            Stopwatch sw = Stopwatch.StartNew();
            (options.Password, options.KdfSalt) = TestData.Data.Stretch(len: 12, options: options);
            byte[] pwd = options.Password;
            HybridAlgorithmHelper.StretchPassword(options);
            Assert.IsNotNull(options.CounterKdfSalt);
            Assert.IsFalse(pwd.SequenceEqual(options.Password));
            Console.WriteLine($"\tRuntime {sw.Elapsed}");
        }

        public static void AllSyncEncryptionTests()
        {
            List<string> macSeen = new(),
                asymmetricSeen = new();
            IAsymmetricAlgorithm algo, counterAlgo;
            int done = 0;
            foreach (string name in EncryptionHelper.Algorithms.Keys)
            {
                macSeen.Clear();
                foreach (string macName in MacHelper.Algorithms.Keys)
                    foreach (string counterMacName in MacHelper.Algorithms.Keys)
                    {
                        if (MacHelper.Algorithms.Count != 1 && macName == counterMacName) continue;
                        if (macSeen.Contains($"{macName} {counterMacName}") || macSeen.Contains($"{counterMacName} {macName}")) continue;
                        macSeen.Add($"{macName} {counterMacName}");
                        asymmetricSeen.Clear();
                        foreach (string asymmetricName in AsymmetricHelper.Algorithms.Keys)
                        {
                            algo = AsymmetricHelper.GetAlgorithm(asymmetricName);
                            if (!algo.CanExchangeKey) continue;
                            foreach (string counterAsymmetricName in AsymmetricHelper.Algorithms.Keys)
                            {
                                counterAlgo = AsymmetricHelper.GetAlgorithm(counterAsymmetricName);
                                if (!counterAlgo.CanExchangeKey) continue;
                                if (AsymmetricHelper.Algorithms.Count != 1 && asymmetricName == counterAsymmetricName) continue;
                                if (asymmetricSeen.Contains($"{asymmetricName} {counterAsymmetricName}") || asymmetricSeen.Contains($"{counterAsymmetricName} {asymmetricName}"))
                                    continue;
                                asymmetricSeen.Add($"{asymmetricName} {counterAsymmetricName}");
                                foreach (int keySize in algo.AllowedKeySizes)
                                    foreach (int counterKeySize in counterAlgo.AllowedKeySizes)
                                    {
                                        if (algo.AllowedKeySizes.Count != 1 && keySize == counterKeySize) continue;
                                        SyncEncryptionTests(new()
                                        {
                                            Algorithm = name,
                                            MacAlgorithm = macName,
                                            CounterMacAlgorithm = counterMacName,
                                            AsymmetricAlgorithm = asymmetricName,
                                            AsymmetricCounterAlgorithm = counterAsymmetricName,
                                            RequireCounterMac = true,
                                            KdfAlgorithmIncluded = false,
                                            RequireKdf = false,
                                            LeaveOpen = true
                                        }, keySize, counterKeySize);
                                        done++;
                                    }
                            }
                        }
                    }
            }
            Console.WriteLine($"{done} tests done");
        }

        public static async Task AllAsyncEncryptionTests()
        {
            List<string> macSeen = new(),
                asymmetricSeen = new();
            IAsymmetricAlgorithm algo, counterAlgo;
            int done = 0;
            foreach (string name in EncryptionHelper.Algorithms.Keys)
            {
                macSeen.Clear();
                foreach (string macName in MacHelper.Algorithms.Keys)
                    foreach (string counterMacName in MacHelper.Algorithms.Keys)
                    {
                        if (MacHelper.Algorithms.Count != 1 && macName == counterMacName) continue;
                        if (macSeen.Contains($"{macName} {counterMacName}") || macSeen.Contains($"{counterMacName} {macName}")) continue;
                        macSeen.Add($"{macName} {counterMacName}");
                        asymmetricSeen.Clear();
                        foreach (string asymmetricName in AsymmetricHelper.Algorithms.Keys)
                        {
                            algo = AsymmetricHelper.GetAlgorithm(asymmetricName);
                            if (!algo.CanExchangeKey) continue;
                            foreach (string counterAsymmetricName in AsymmetricHelper.Algorithms.Keys)
                            {
                                counterAlgo = AsymmetricHelper.GetAlgorithm(counterAsymmetricName);
                                if (!counterAlgo.CanExchangeKey) continue;
                                if (AsymmetricHelper.Algorithms.Count != 1 && asymmetricName == counterAsymmetricName) continue;
                                if (asymmetricSeen.Contains($"{asymmetricName} {counterAsymmetricName}") || asymmetricSeen.Contains($"{counterAsymmetricName} {asymmetricName}"))
                                    continue;
                                asymmetricSeen.Add($"{asymmetricName} {counterAsymmetricName}");
                                foreach (int keySize in algo.AllowedKeySizes)
                                    foreach (int counterKeySize in counterAlgo.AllowedKeySizes)
                                    {
                                        if (algo.AllowedKeySizes.Count != 1 && keySize == counterKeySize) continue;
                                        await AsyncEncryptionTests(new()
                                        {
                                            Algorithm = name,
                                            MacAlgorithm = macName,
                                            CounterMacAlgorithm = counterMacName,
                                            AsymmetricAlgorithm = asymmetricName,
                                            AsymmetricCounterAlgorithm = counterAsymmetricName,
                                            RequireCounterMac = true,
                                            KdfAlgorithmIncluded = false,
                                            RequireKdf = false,
                                            LeaveOpen = true
                                        }, keySize, counterKeySize);
                                        done++;
                                    }
                            }
                        }
                    }
            }
            Console.WriteLine($"{done} tests done");
        }

        public static void SyncEncryptionTests(CryptoOptions options, int keySize, int counterKeySize)
        {
            Console.WriteLine($"Synchronous hybrid encryption tests with {options.Algorithm}");
            Console.WriteLine($"\tMAC algorithms: {options.MacAlgorithm} and {options.CounterMacAlgorithm}");
            Console.WriteLine($"\tAsymmetric algorithms: {options.AsymmetricAlgorithm} ({keySize}) and {options.AsymmetricCounterAlgorithm} ({counterKeySize})");
            options.Tracer = new();
            try
            {
                Stopwatch sw = Stopwatch.StartNew();
                // With password
                Console.WriteLine("\t\tWith password");
                using MemoryStream data = new(TestData.Data);
                using MemoryStream cipher = new();
                data.Encrypt(cipher, TestData.Key, options);
                using MemoryStream raw = new();
                cipher.Position = 0;
                cipher.Decrypt(raw, TestData.Key, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(data.ToArray()));
                // With asymmetric key
                Console.WriteLine("\t\tWith asymmetric key");
                options.KeyExchangeDataIncluded = true;
                options.RequireKeyExchangeData = true;
                options.RequireAsymmetricCounterAlgorithm = true;
                IAsymmetricAlgorithm algo = AsymmetricHelper.GetAlgorithm(options.AsymmetricAlgorithm!),
                    counterAlgo = AsymmetricHelper.GetAlgorithm(options.AsymmetricCounterAlgorithm!);
                options.AsymmetricKeyBits = keySize;
                using IAsymmetricPrivateKey privateKey = algo.CreateKeyPair(options);
                options.AsymmetricKeyBits = counterKeySize;
                using IAsymmetricPrivateKey privateKey2 = counterAlgo.CreateKeyPair(options);
                options.CounterPrivateKey = privateKey2;
                cipher.SetLength(0);
                raw.SetLength(0);
                data.Position = 0;
                data.Encrypt(cipher, privateKey, options);
                cipher.Position = 0;
                cipher.Decrypt(raw, privateKey, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(data.ToArray()));
                Console.WriteLine($"\tRuntime {sw.Elapsed}");
            }
            catch
            {
                options.Tracer.Flush();
            }
        }

        public static async Task AsyncEncryptionTests(CryptoOptions options, int keySize, int counterKeySize)
        {
            Console.WriteLine($"Asynchronous hybrid encryption tests with {options.Algorithm}");
            Console.WriteLine($"\tMAC algorithms: {options.MacAlgorithm} and {options.CounterMacAlgorithm}");
            Console.WriteLine($"\tAsymmetric algorithms: {options.AsymmetricAlgorithm} and {options.AsymmetricCounterAlgorithm}");
            options.Tracer = new();
            try
            {
                Stopwatch sw = Stopwatch.StartNew();
                // With password
                Console.WriteLine("\t\tWith password");
                using MemoryStream data = new(TestData.Data);
                using MemoryStream cipher = new();
                await data.EncryptAsync(cipher, TestData.Key, options);
                using MemoryStream raw = new();
                cipher.Position = 0;
                await cipher.DecryptAsync(raw, TestData.Key, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(data.ToArray()));
                // With asymmetric key
                Console.WriteLine("\t\tWith asymmetric key");
                options.KeyExchangeDataIncluded = true;
                options.RequireKeyExchangeData = true;
                options.RequireAsymmetricCounterAlgorithm = true;
                IAsymmetricAlgorithm algo = AsymmetricHelper.GetAlgorithm(options.AsymmetricAlgorithm!),
                    counterAlgo = AsymmetricHelper.GetAlgorithm(options.AsymmetricCounterAlgorithm!);
                options.AsymmetricKeyBits = keySize;
                using IAsymmetricPrivateKey privateKey = algo.CreateKeyPair(options);
                options.AsymmetricKeyBits = counterKeySize;
                using IAsymmetricPrivateKey privateKey2 = counterAlgo.CreateKeyPair(options);
                options.CounterPrivateKey = privateKey2;
                cipher.SetLength(0);
                raw.SetLength(0);
                data.Position = 0;
                await data.EncryptAsync(cipher, privateKey, options);
                cipher.Position = 0;
                await cipher.DecryptAsync(raw, privateKey, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(data.ToArray()));
                Console.WriteLine($"\tRuntime {sw.Elapsed}");
            }
            catch
            {
                options.Tracer.Flush();
            }
        }
    }
}
