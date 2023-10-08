using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;

namespace wan24.Crypto.Tests
{
    public static class EncryptionTests
    {
        public static async Task TestAllAlgorithms()
        {
            Assert.IsFalse(EncryptionHelper.Algorithms.IsEmpty);
            int done = 0;
            foreach (string name in EncryptionHelper.Algorithms.Keys)
            {
                AlgorithmTests(name);
                await AlgorithmTestsAsync(name);
                done += 2;
            }
            Console.WriteLine($"{done} tests done");
        }

        public static void AlgorithmTests(string name)
        {
            Console.WriteLine($"Synchronous encryption {name} tests");
            CryptoOptions options = new()
            {
                Algorithm = name,
                LeaveOpen = true
            };
            options.WithoutKdf();
            Stopwatch sw = Stopwatch.StartNew();
            {
                byte[] cipher = TestData.Data.Encrypt(TestData.Key, options),
                    raw = cipher.Decrypt(TestData.Key, options);
                Assert.IsTrue(raw.SequenceEqual(TestData.Data));
                Assert.IsTrue(new byte[] { 1, 2, 3 }.SequenceEqual(TestData.Key));
                using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
                cipher = TestData.Data.Encrypt(key, options);
                raw = cipher.Decrypt(key, options);
                Assert.IsTrue(raw.SequenceEqual(TestData.Data));
                Assert.IsTrue(new byte[] { 1, 2, 3 }.SequenceEqual(TestData.Key));
            }
            {
                using MemoryStream ms = new(TestData.Data);
                using MemoryStream cipher = new();
                ms.Encrypt(cipher, TestData.Key, options);
                cipher.Position = 0;
                using MemoryStream raw = new();
                cipher.Decrypt(raw, TestData.Key, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(TestData.Data));
                Assert.IsTrue(new byte[] { 1, 2, 3 }.SequenceEqual(TestData.Key));
                cipher.SetLength(0);
                raw.SetLength(0);
                ms.Position = 0;
                using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
                ms.Encrypt(cipher, key, options);
                cipher.Position = 0;
                cipher.Decrypt(raw, key, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(TestData.Data));
                Assert.IsTrue(new byte[] { 1, 2, 3 }.SequenceEqual(TestData.Key));
            }
            Console.WriteLine($"\tRuntime {sw.Elapsed}");
        }

        public static async Task AlgorithmTestsAsync(string name)
        {
            Console.WriteLine($"Asynchronous encryption {name} tests");
            CryptoOptions options = new()
            {
                Algorithm = name,
                LeaveOpen = true
            };
            options.WithoutKdf();
            Stopwatch sw = Stopwatch.StartNew();
            using MemoryStream ms = new(TestData.Data);
            using MemoryStream cipher = new();
            await ms.EncryptAsync(cipher, TestData.Key, options);
            cipher.Position = 0;
            using MemoryStream raw = new();
            await cipher.DecryptAsync(raw, TestData.Key, options);
            Assert.IsTrue(raw.ToArray().SequenceEqual(TestData.Data));
            Assert.IsTrue(new byte[] { 1, 2, 3 }.SequenceEqual(TestData.Key));
            cipher.SetLength(0);
            raw.SetLength(0);
            ms.Position = 0;
            using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
            await ms.EncryptAsync(cipher, key, options);
            cipher.Position = 0;
            await cipher.DecryptAsync(raw, key, options);
            Assert.IsTrue(raw.ToArray().SequenceEqual(TestData.Data));
            Assert.IsTrue(new byte[] { 1, 2, 3 }.SequenceEqual(TestData.Key));
            Console.WriteLine($"\tRuntime {sw.Elapsed}");
        }
    }
}
