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
            foreach (string name in AsymmetricHelper.Algorithms.Keys)
            {
                AlgorithmTests(name);
                done++;
            }
            Console.WriteLine($"{done} tests done");
        }

        public static void AlgorithmTests(string name)
        {
            Console.WriteLine($"Asymmetric algorithm {name} tests");
            Stopwatch sw = Stopwatch.StartNew();
            IAsymmetricAlgorithm algo = AsymmetricHelper.GetAlgorithm(name);
            Assert.AreEqual(name, algo.Name);
            using IAsymmetricPrivateKey privateKey = algo.CreateKeyPair();
            if (algo.CanExchangeKey)
            {
                Console.WriteLine("\tExecute key exchange tests");
                using IKeyExchangePrivateKey privateKey2 = (IKeyExchangePrivateKey)algo.CreateKeyPair();
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
