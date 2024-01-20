using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;

namespace wan24.Crypto.Tests
{
    public static class AsymmetricTests
    {
        public static void TestAllAlgorithms()
        {
            Assert.IsFalse(AsymmetricHelper.Algorithms.IsEmpty);
            int done = 0;
            IAsymmetricAlgorithm algo;
            foreach (string name in AsymmetricHelper.Algorithms.Keys)
            {
                try
                {
                    algo = AsymmetricHelper.GetAlgorithm(name);
                }
                catch
                {
                    Console.WriteLine($"Failed to load asymmetric algorithm \"{name}\"");
                    throw;
                }
                foreach (int bits in algo.AllowedKeySizes)
                {
                    AlgorithmTests(name, bits);
                    done++;
                }
            }
            Console.WriteLine($"{done} tests done");
        }

        public static void AlgorithmTests(string name, int bits)
        {
            Console.WriteLine($"Asymmetric algorithm {name} tests with {bits} bit key size");
            Stopwatch sw = Stopwatch.StartNew();
            IAsymmetricAlgorithm algo = AsymmetricHelper.GetAlgorithm(name);
            Assert.AreEqual(name, algo.Name);
            CryptoOptions options = new()
            {
                AsymmetricKeyBits = bits
            };
            using IAsymmetricPrivateKey privateKey = algo.CreateKeyPair(options);
            {
                Console.WriteLine("\tExecute serialization tests");
                byte[] serialized = privateKey.Export();
                using IAsymmetricKey imported = AsymmetricKeyBase.Import(serialized);
                IAsymmetricPrivateKey? importedPrivateKey = imported as IAsymmetricPrivateKey;
                Assert.IsTrue(importedPrivateKey is not null);
                Assert.AreEqual(privateKey.GetType(), imported.GetType());
                Assert.IsTrue(privateKey.ID.SequenceEqual(imported.ID));
                Assert.AreEqual(privateKey.Bits, imported.Bits);
                IAsymmetricPublicKey? importedPublicKey = importedPrivateKey.PublicKey;
                serialized = importedPublicKey.Export();
                importedPublicKey = AsymmetricKeyBase.Import(serialized) as IAsymmetricPublicKey;
                Assert.IsTrue(importedPublicKey is not null);
                Assert.IsTrue(privateKey.PublicKey.ID.SequenceEqual(importedPublicKey.ID));
                Assert.IsTrue(privateKey.ID.SequenceEqual(importedPublicKey.ID));
            }
            if (algo.CanExchangeKey)
            {
                Console.WriteLine("\tExecute key exchange tests");
                using IKeyExchangePrivateKey privateKey2 = (IKeyExchangePrivateKey)algo.CreateKeyPair(options);
                (byte[] key2, byte[] ked) = privateKey2.GetKeyExchangeData(privateKey.PublicKey);
                byte[] key1 = ((IKeyExchangePrivateKey)privateKey).DeriveKey(ked);
                Assert.IsTrue(key1.SequenceEqual(key2));
            }
            if (algo.CanSign)
            {
                Console.WriteLine("\tExecute signature tests");
                SignatureContainer signature = ((ISignaturePrivateKey)privateKey).SignData(TestData.Data, "test");
                byte[] signatureBytes = (byte[])signature;
                signature = (SignatureContainer)signatureBytes;
                Assert.IsTrue(signature.ValidateSignedData(TestData.Data, throwOnError: false));
                Assert.IsFalse(signature.ValidateSignedData(Array.Empty<byte>(), throwOnError: false));
                Assert.ThrowsException<CryptographicException>(() => signature.ValidateSignedData(Array.Empty<byte>()));
                Assert.IsTrue(((ISignaturePublicKey)privateKey.PublicKey).ValidateSignature(signature, TestData.Data, throwOnError: false));
                Assert.IsFalse(((ISignaturePublicKey)privateKey.PublicKey).ValidateSignature(signature, Array.Empty<byte>(), throwOnError: false));
                Assert.ThrowsException<CryptographicException>(() => ((ISignaturePublicKey)privateKey.PublicKey).ValidateSignature(signature, Array.Empty<byte>()));
            }
            Console.WriteLine($"\t\tRuntime {sw.Elapsed}");
        }
    }
}
