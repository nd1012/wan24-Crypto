﻿using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Asymmetric_Tests
    {
        public static readonly byte[] Data = new byte[] { 1, 2, 3 };

        [TestMethod]
        public void AllAlgo_Tests()
        {
            Assert.IsTrue(AsymmetricHelper.Algorithms.Count > 0);
            foreach (string name in AsymmetricHelper.Algorithms.Keys) Algo_Tests(name);
        }

        [TestMethod]
        public void Pki_Tests()
        {
            // Self-signed root key
            using ISignaturePrivateKey privateRootKey = AsymmetricHelper.CreateSignatureKeyPair();
            using AsymmetricPublicKeySigningRequest rootKeySigningRequest = new(privateRootKey.PublicKey);
            using AsymmetricSignedPublicKey signedRootPublicKey = rootKeySigningRequest.GetAsUnsignedKey();
            signedRootPublicKey.Sign(privateRootKey);
            // Signed key
            using ISignaturePrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair();
            using AsymmetricPublicKeySigningRequest keySigningRequest = new(privateKey.PublicKey);
            using AsymmetricSignedPublicKey signedPublicKey = keySigningRequest.GetAsUnsignedKey();
            signedPublicKey.Sign(privateRootKey);
            // Setup PKI infrastructure for signed key validation
            AsymmetricSignedPublicKey.RootTrust = (id) => id.SequenceEqual(signedRootPublicKey.PublicKey.ID);
            AsymmetricSignedPublicKey.SignedPublicKeyStore = (id) =>
            {
                if (id.SequenceEqual(signedRootPublicKey.PublicKey.ID)) return signedRootPublicKey;
                if (id.SequenceEqual(signedPublicKey.PublicKey.ID)) return signedPublicKey;
                return null;
            };
            // Validate the signed key
            signedPublicKey.Validate();
            // Test key revocation
            AsymmetricSignedPublicKey.SignedPublicKeyRevocation = (id) => true;
            Assert.IsFalse(signedPublicKey.Validate(throwOnError: false));
            Assert.ThrowsException<CryptographicException>(() => signedPublicKey.Validate());
        }

        [TestMethod]
        public void AsymmetricHelper_Tests()
        {
            Assert.AreEqual(AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME, AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name);
            Assert.AreEqual(AsymmetricHelper.DefaultKeyExchangeAlgorithm, AsymmetricHelper.GetAlgorithm(AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name));
            Assert.AreEqual(AsymmetricHelper.DefaultKeyExchangeAlgorithm, AsymmetricHelper.GetAlgorithm(AsymmetricHelper.DefaultKeyExchangeAlgorithm.Value));
            Assert.AreEqual(AsymmetricEcDsaAlgorithm.ALGORITHM_NAME, AsymmetricHelper.DefaultSignatureAlgorithm.Name);
            Assert.AreEqual(AsymmetricHelper.DefaultSignatureAlgorithm, AsymmetricHelper.GetAlgorithm(AsymmetricHelper.DefaultSignatureAlgorithm.Name));
            Assert.AreEqual(AsymmetricHelper.DefaultSignatureAlgorithm, AsymmetricHelper.GetAlgorithm(AsymmetricHelper.DefaultSignatureAlgorithm.Value));
        }

        public void Algo_Tests(string name)
        {
            Console.WriteLine($"Asymmetric algorithm {name} tests");
            IAsymmetricAlgorithm algo = AsymmetricHelper.GetAlgorithm(name);
            Assert.AreEqual(name, algo.Name);
            using IAsymmetricPrivateKey privateKey = algo.CreateKeyPair();
            if (algo.CanExchangeKey)
            {
                Console.WriteLine("\tExecute key exchange tests");
                using IKeyExchangePrivateKey privateKey2 = (IKeyExchangePrivateKey)algo.CreateKeyPair();
                (byte[] key, byte[] kex) = privateKey2.GetKeyExchangeData(privateKey.PublicKey);
                byte[] key2 = privateKey2.DeriveKey(kex);
                Assert.IsTrue(key.SequenceEqual(key2));
            }
            else
            {
                Console.WriteLine("\tExecute signature tests");
                SignatureContainer signature = ((ISignaturePrivateKey)privateKey).SignData(Data, "test");
                Assert.IsTrue(signature.ValidateSignedData(Data, throwOnError: false));
                Assert.IsFalse(signature.ValidateSignedData(Array.Empty<byte>(), throwOnError: false));
                Assert.ThrowsException<CryptographicException>(() => signature.ValidateSignedData(Array.Empty<byte>()));
                Assert.IsTrue(((ISignaturePublicKey)privateKey.PublicKey).ValidateSignature(signature, Data, throwOnError: false));
                Assert.IsFalse(((ISignaturePublicKey)privateKey.PublicKey).ValidateSignature(signature, Array.Empty<byte>(), throwOnError: false));
                Assert.ThrowsException<CryptographicException>(() => ((ISignaturePublicKey)privateKey.PublicKey).ValidateSignature(signature, Array.Empty<byte>()));
            }
        }
    }
}
