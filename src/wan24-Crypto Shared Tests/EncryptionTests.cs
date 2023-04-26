namespace wan24.Crypto.Tests
{
    public static class EncryptionTests
    {
        public static async Task TestAllAlgorithms()
        {
            Assert.IsTrue(EncryptionHelper.Algorithms.Count > 0);
            foreach (string name in EncryptionHelper.Algorithms.Keys)
            {
                AlgorithmTests(name);
                await AlgorithmTestsAsync(name);
            }
        }

        public static void AlgorithmTests(string name)
        {
            Console.WriteLine($"Synchronous encryption {name} tests");
            {
                byte[] cipher = TestData.Data.Encrypt(TestData.Key),
                    raw = cipher.Decrypt(TestData.Key);
                Assert.IsTrue(raw.SequenceEqual(TestData.Data));
                using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
                cipher = TestData.Data.Encrypt(key);
                raw = cipher.Decrypt(key);
                Assert.IsTrue(raw.SequenceEqual(TestData.Data));
            }
            {
                CryptoOptions options = new()
                {
                    Algorithm = name,
                    LeaveOpen = true
                };
                using MemoryStream ms = new(TestData.Data);
                using MemoryStream cipher = new();
                ms.Encrypt(cipher, TestData.Key, options);
                cipher.Position = 0;
                using MemoryStream raw = new();
                cipher.Decrypt(raw, TestData.Key, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(TestData.Data));
                cipher.SetLength(0);
                raw.SetLength(0);
                ms.Position = 0;
                using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
                ms.Encrypt(cipher, key, options);
                cipher.Position = 0;
                cipher.Decrypt(raw, key, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(TestData.Data));
            }
        }

        public static async Task AlgorithmTestsAsync(string name)
        {
            Console.WriteLine($"Asynchronous encryption {name} tests");
            CryptoOptions options = new()
            {
                Algorithm = name,
                LeaveOpen = true
            };
            using MemoryStream ms = new(TestData.Data);
            using MemoryStream cipher = new();
            await ms.EncryptAsync(cipher, TestData.Key, options);
            cipher.Position = 0;
            using MemoryStream raw = new();
            await cipher.DecryptAsync(raw, TestData.Key, options);
            Assert.IsTrue(raw.ToArray().SequenceEqual(TestData.Data));
            cipher.SetLength(0);
            raw.SetLength(0);
            ms.Position = 0;
            using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
            await ms.EncryptAsync(cipher, key, options);
            cipher.Position = 0;
            await cipher.DecryptAsync(raw, key, options);
            Assert.IsTrue(raw.ToArray().SequenceEqual(TestData.Data));
        }
    }
}
