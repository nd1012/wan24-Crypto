using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace wan24.Crypto.Tests
{
    public static class HybridTests
    {
        public static void AllAsymmetricTests()
        {
            List<string> seen = new();
            IAsymmetricAlgorithm algo, counterAlgo;
            foreach (string name in AsymmetricHelper.Algorithms.Keys)
                foreach (string counterName in AsymmetricHelper.Algorithms.Keys)
                {
                    //if (name == counterName) continue;
                    if (seen.Contains($"{name} {counterName}")) continue;
                    seen.Add($"{name} {counterName}");
                    algo = AsymmetricHelper.GetAlgorithm(name);
                    counterAlgo = AsymmetricHelper.GetAlgorithm(counterName);
                    if (algo.CanExchangeKey != counterAlgo.CanExchangeKey && algo.CanSign != counterAlgo.CanSign) continue;
                    AsymmetricTests(new()
                    {
                        AsymmetricAlgorithm = name,
                        AsymmetricCounterAlgorithm = counterName
                    });
                }
        }

        public static void AsymmetricTests(CryptoOptions options)
        {
            Console.WriteLine($"Hybrid asymmetric tests with {options.AsymmetricAlgorithm} and counter {options.AsymmetricCounterAlgorithm}");
            IAsymmetricAlgorithm algo = AsymmetricHelper.GetAlgorithm(options.AsymmetricAlgorithm!),
                counterAlgo = AsymmetricHelper.GetAlgorithm(options.AsymmetricCounterAlgorithm!);
            if (algo.CanExchangeKey && counterAlgo.CanExchangeKey)
            {
                Console.WriteLine("\tRunning key exchange tests");
                options.AsymmetricAlgorithm = algo.Name;
                options.AsymmetricKeyBits = algo.DefaultKeySize;
                using IKeyExchangePrivateKey privateKey = AsymmetricHelper.CreateKeyExchangeKeyPair(options);
                options.AsymmetricAlgorithm = counterAlgo.Name;
                options.AsymmetricKeyBits = counterAlgo.DefaultKeySize;
                using IKeyExchangePrivateKey privateKey2 = AsymmetricHelper.CreateKeyExchangeKeyPair(options);
                options.AsymmetricAlgorithm = algo.Name;
                options.AsymmetricCounterAlgorithm = counterAlgo.Name;
                options.PrivateKey = privateKey;
                options.CounterPrivateKey = privateKey2;
                KeyExchangeDataContainer keyExchangeData = new();
                (options.Password, keyExchangeData.KeyExchangeData) = privateKey.GetKeyExchangeData(options: options);
                HybridAlgorithmHelper.GetKeyExchangeData(keyExchangeData, options);
                Assert.IsNotNull(keyExchangeData.CounterKeyExchangeData);
                byte[] key1 = options.Password;
                HybridAlgorithmHelper.DeriveKey(keyExchangeData, options);
                Assert.IsTrue(key1.SequenceEqual(options.Password));
            }
            if (algo.CanSign && counterAlgo.CanSign)
            {
                Console.WriteLine("\tRunning signature tests");
                options.AsymmetricKeyBits = algo.DefaultKeySize;
                using ISignaturePrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair(options);
                options.AsymmetricAlgorithm = options.AsymmetricCounterAlgorithm;
                options.AsymmetricKeyBits = counterAlgo.DefaultKeySize;
                using ISignaturePrivateKey privateKey2 = AsymmetricHelper.CreateSignatureKeyPair(options);
                options.AsymmetricCounterAlgorithm = options.AsymmetricAlgorithm;
                options.AsymmetricAlgorithm = privateKey.Algorithm.Name;
                options.CounterPrivateKey = privateKey2;
                SignatureContainer signature = privateKey.SignData(TestData.Data, "Test", options);
                HybridAlgorithmHelper.Sign(signature, options);
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
        }

        public static void AllMacTests()
        {
            List<string> seen = new();
            foreach (string name in MacHelper.Algorithms.Keys)
                foreach (string counterName in MacHelper.Algorithms.Keys)
                {
                    if (name == counterName) continue;
                    if (seen.Contains($"{name} {counterName}")) continue;
                    seen.Add($"{name} {counterName}");
                    MacTests(new()
                    {
                        MacAlgorithm = name,
                        CounterMacAlgorithm = counterName
                    });
                }
        }

        public static void MacTests(CryptoOptions options)
        {
            Console.WriteLine($"Hybrid MAC tests with {options.MacAlgorithm} and counter {options.CounterMacAlgorithm}");
            byte[] mac = options.Mac = TestData.Data.Mac(TestData.Key, options);
            options.Password = TestData.Key;
            HybridAlgorithmHelper.ComputeMac(options);
            Assert.IsFalse(mac.SequenceEqual(options.Mac));
            Assert.AreEqual(MacHelper.GetAlgorithm(options.CounterMacAlgorithm!).MacLength, options.Mac.Length);
        }

        public static void AllKdfTests()
        {
            List<string> seen = new();
            foreach (string name in KdfHelper.Algorithms.Keys)
                foreach (string counterName in KdfHelper.Algorithms.Keys)
                {
                    //if (name == counterName) continue;
                    if (seen.Contains($"{name} {counterName}")) continue;
                    seen.Add($"{name} {counterName}");
                    KdfTests(new()
                    {
                        KdfAlgorithm = name,
                        KdfIterations = KdfHelper.GetAlgorithm(name).DefaultIterations,
                        CounterKdfAlgorithm = counterName,
                        CounterKdfIterations = KdfHelper.GetAlgorithm(counterName).DefaultIterations
                    });
                }
        }

        public static void KdfTests(CryptoOptions options)
        {
            Console.WriteLine($"Hybrid KDF tests with {options.KdfAlgorithm} and counter {options.CounterKdfAlgorithm}");
            (options.Password, options.KdfSalt) = TestData.Data.Stretch(len: 12, options: options);
            byte[] pwd = options.Password;
            HybridAlgorithmHelper.StretchPassword(options);
            Assert.IsNotNull(options.CounterKdfSalt);
            Assert.IsFalse(pwd.SequenceEqual(options.Password));
        }

        public static void AllSyncEncryptionTests()
        {
            List<string> macSeen = new(),
                asymmetricSeen = new(),
                kdfSeen = new();
            foreach (string name in EncryptionHelper.Algorithms.Keys)
            {
                macSeen.Clear();
                foreach (string macName in MacHelper.Algorithms.Keys)
                    foreach (string counterMacName in MacHelper.Algorithms.Keys)
                    {
                        if (macName == counterMacName) continue;
                        if (macSeen.Contains($"{macName} {counterMacName}")) continue;
                        macSeen.Add($"{macName} {counterMacName}");
                        asymmetricSeen.Clear();
                        foreach (string asymmetricName in AsymmetricHelper.Algorithms.Keys)
                        {
                            if (!AsymmetricHelper.GetAlgorithm(asymmetricName).CanExchangeKey) continue;
                            foreach (string counterAsymmetricName in AsymmetricHelper.Algorithms.Keys)
                            {
                                if (!AsymmetricHelper.GetAlgorithm(counterAsymmetricName).CanExchangeKey) continue;
                                //if (asymmetricName == counterAsymmetricName) continue;
                                if (asymmetricSeen.Contains($"{asymmetricName} {counterAsymmetricName}")) continue;
                                asymmetricSeen.Add($"{asymmetricName} {counterAsymmetricName}");
                                kdfSeen.Clear();
                                foreach (string kdfName in KdfHelper.Algorithms.Keys)
                                    foreach (string counterKdfName in KdfHelper.Algorithms.Keys)
                                    {
                                        //if (kdfName == counterKdfName) continue;
                                        if (kdfSeen.Contains($"{kdfName} {counterKdfName}")) continue;
                                        kdfSeen.Add($"{kdfName} {counterKdfName}");
                                        SyncEncryptionTests(new()
                                        {
                                            Algorithm = name,
                                            MacAlgorithm = macName,
                                            CounterMacAlgorithm = counterMacName,
                                            AsymmetricAlgorithm = asymmetricName,
                                            AsymmetricCounterAlgorithm = counterAsymmetricName,
                                            KdfAlgorithm = kdfName,
                                            KdfIterations = KdfHelper.GetAlgorithm(kdfName).DefaultIterations,
                                            CounterKdfAlgorithm = counterKdfName,
                                            CounterKdfIterations = KdfHelper.GetAlgorithm(counterKdfName).DefaultIterations,
                                            RequireCounterMac = true,
                                            RequireCounterKdf = true,
                                            LeaveOpen = true
                                        });
                                    }
                            }
                        }
                    }
            }
        }

        public static async Task AllAsyncEncryptionTests()
        {
            List<string> macSeen = new(),
                asymmetricSeen = new(),
                kdfSeen = new();
            foreach (string name in EncryptionHelper.Algorithms.Keys)
            {
                macSeen.Clear();
                foreach (string macName in MacHelper.Algorithms.Keys)
                    foreach (string counterMacName in MacHelper.Algorithms.Keys)
                    {
                        if (macName == counterMacName) continue;
                        if (macSeen.Contains($"{macName} {counterMacName}")) continue;
                        macSeen.Add($"{macName} {counterMacName}");
                        asymmetricSeen.Clear();
                        foreach (string asymmetricName in AsymmetricHelper.Algorithms.Keys)
                        {
                            if (!AsymmetricHelper.GetAlgorithm(asymmetricName).CanExchangeKey) continue;
                            foreach (string counterAsymmetricName in AsymmetricHelper.Algorithms.Keys)
                            {
                                if (!AsymmetricHelper.GetAlgorithm(counterAsymmetricName).CanExchangeKey) continue;
                                //if (asymmetricName == counterAsymmetricName) continue;
                                if (asymmetricSeen.Contains($"{asymmetricName} {counterAsymmetricName}")) continue;
                                asymmetricSeen.Add($"{asymmetricName} {counterAsymmetricName}");
                                kdfSeen.Clear();
                                foreach (string kdfName in KdfHelper.Algorithms.Keys)
                                    foreach (string counterKdfName in KdfHelper.Algorithms.Keys)
                                    {
                                        //if (kdfName == counterKdfName) continue;
                                        if (kdfSeen.Contains($"{kdfName} {counterKdfName}")) continue;
                                        kdfSeen.Add($"{kdfName} {counterKdfName}");
                                        await AsyncEncryptionTests(new()
                                        {
                                            Algorithm = name,
                                            MacAlgorithm = macName,
                                            CounterMacAlgorithm = counterMacName,
                                            AsymmetricAlgorithm = asymmetricName,
                                            AsymmetricCounterAlgorithm = counterAsymmetricName,
                                            KdfAlgorithm = kdfName,
                                            KdfIterations = KdfHelper.GetAlgorithm(kdfName).DefaultIterations,
                                            CounterKdfAlgorithm = counterKdfName,
                                            CounterKdfIterations = KdfHelper.GetAlgorithm(counterKdfName).DefaultIterations,
                                            RequireCounterMac = true,
                                            RequireCounterKdf = true,
                                            LeaveOpen = true
                                        });
                                    }
                            }
                        }
                    }
            }
        }

        public static void SyncEncryptionTests(CryptoOptions options)
        {
            Console.WriteLine($"Synchronous hybrid encryption tests with {options.Algorithm}");
            Console.WriteLine($"\tMAC algorithms: {options.MacAlgorithm} and {options.CounterMacAlgorithm}");
            Console.WriteLine($"\tAsymmetric algorithms: {options.AsymmetricAlgorithm} and {options.AsymmetricCounterAlgorithm}");
            Console.WriteLine($"\tKDF algorithms: {options.KdfAlgorithm} and {options.CounterKdfAlgorithm}");
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
            options.AsymmetricKeyBits = algo.DefaultKeySize;
            using IAsymmetricPrivateKey privateKey = algo.CreateKeyPair(options);
            options.AsymmetricKeyBits = counterAlgo.DefaultKeySize;
            using IAsymmetricPrivateKey privateKey2 = counterAlgo.CreateKeyPair(options);
            options.CounterPrivateKey = privateKey2;
            cipher.SetLength(0);
            raw.SetLength(0);
            data.Position = 0;
            data.Encrypt(cipher, privateKey, options);
            cipher.Position = 0;
            cipher.Decrypt(raw, privateKey, options);
            Assert.IsTrue(raw.ToArray().SequenceEqual(data.ToArray()));
        }

        public static async Task AsyncEncryptionTests(CryptoOptions options)
        {
            Console.WriteLine($"Asynchronous hybrid encryption tests with {options.Algorithm}");
            Console.WriteLine($"\tMAC algorithms: {options.MacAlgorithm} and {options.CounterMacAlgorithm}");
            Console.WriteLine($"\tAsymmetric algorithms: {options.AsymmetricAlgorithm} and {options.AsymmetricCounterAlgorithm}");
            Console.WriteLine($"\tKDF algorithms: {options.KdfAlgorithm} and {options.CounterKdfAlgorithm}");
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
            options.AsymmetricKeyBits = algo.DefaultKeySize;
            using IAsymmetricPrivateKey privateKey = algo.CreateKeyPair(options);
            options.AsymmetricKeyBits = counterAlgo.DefaultKeySize;
            using IAsymmetricPrivateKey privateKey2 = counterAlgo.CreateKeyPair(options);
            options.CounterPrivateKey = privateKey2;
            cipher.SetLength(0);
            raw.SetLength(0);
            data.Position = 0;
            await data.EncryptAsync(cipher, privateKey, options);
            cipher.Position = 0;
            await cipher.DecryptAsync(raw, privateKey, options);
            Assert.IsTrue(raw.ToArray().SequenceEqual(data.ToArray()));
        }
    }
}
