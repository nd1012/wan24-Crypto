using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Encryption_Tests
    {
        public static readonly byte[] Data = new byte[] { 1, 2, 3 };
        public static readonly byte[] Key = new byte[] { 1, 2, 3 };

        [TestMethod]
        public void AllSync_Tests()
        {
            Assert.IsTrue(EncryptionHelper.Algorithms.Count > 0);
            foreach (string name in EncryptionHelper.Algorithms.Keys) Sync_Tests(name);
        }

        [TestMethod]
        public async Task AllAsync_Tests()
        {
            Assert.IsTrue(EncryptionHelper.Algorithms.Count > 0);
            foreach (string name in EncryptionHelper.Algorithms.Keys) await Async_Tests(name);
        }

        public void Sync_Tests(string name)
        {
            Console.WriteLine($"Synchronous encryption {name} tests");
            {
                byte[] cipher = Data.Encrypt(Key),
                    raw = cipher.Decrypt(Key);
                Assert.IsTrue(raw.SequenceEqual(Data));
                using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
                cipher = Data.Encrypt(key);
                raw = cipher.Decrypt(key);
                Assert.IsTrue(raw.SequenceEqual(Data));
            }
            {
                CryptoOptions options = new()
                {
                    Algorithm = name,
                    LeaveOpen = true
                };
                using MemoryStream ms = new(Data);
                using MemoryStream cipher = new();
                ms.Encrypt(cipher, Key, options);
                cipher.Position = 0;
                using MemoryStream raw = new();
                cipher.Decrypt(raw, Key, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(Data));
                cipher.SetLength(0);
                raw.SetLength(0);
                ms.Position = 0;
                using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
                ms.Encrypt(cipher, key, options);
                cipher.Position = 0;
                cipher.Decrypt(raw, key, options);
                Assert.IsTrue(raw.ToArray().SequenceEqual(Data));
            }
        }

        public async Task Async_Tests(string name)
        {
            Console.WriteLine($"Asynchronous encryption {name} tests");
            CryptoOptions options = new()
            {
                Algorithm = name,
                LeaveOpen = true
            };
            using MemoryStream ms = new(Data);
            using MemoryStream cipher = new();
            await ms.EncryptAsync(cipher, Key, options);
            cipher.Position = 0;
            using MemoryStream raw = new();
            await cipher.DecryptAsync(raw, Key, options);
            Assert.IsTrue(raw.ToArray().SequenceEqual(Data));
            cipher.SetLength(0);
            raw.SetLength(0);
            ms.Position = 0;
            using IAsymmetricPrivateKey key = AsymmetricHelper.CreateKeyExchangeKeyPair();
            await ms.EncryptAsync(cipher, key, options);
            cipher.Position = 0;
            await cipher.DecryptAsync(raw, key, options);
            Assert.IsTrue(raw.ToArray().SequenceEqual(Data));
        }
    }
}
