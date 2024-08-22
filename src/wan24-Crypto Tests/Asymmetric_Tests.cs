using wan24.Crypto;
using wan24.Crypto.Tests;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Asymmetric_Tests : TestBase
    {
        [TestMethod]
        public void AllAlgo_Tests() => AsymmetricTests.TestAllAlgorithms();

        [TestMethod]
        public async Task Pki_Tests()
        {
            // Self-signed root key
            using ISignaturePrivateKey privateRootKey = AsymmetricHelper.CreateSignatureKeyPair();
            using AsymmetricPublicKeySigningRequest rootKeySigningRequest = new(privateRootKey.PublicKey);
            rootKeySigningRequest.SignRequest(privateRootKey);
            rootKeySigningRequest.ValidateRequestSignature();
            using AsymmetricSignedPublicKey signedRootPublicKey = rootKeySigningRequest.GetAsUnsignedKey();
            signedRootPublicKey.Sign(privateRootKey);
            // Signed key
            using ISignaturePrivateKey privateKey = AsymmetricHelper.CreateSignatureKeyPair();
            using AsymmetricPublicKeySigningRequest keySigningRequest = new(privateKey.PublicKey);
            keySigningRequest.SignRequest(privateKey);
            keySigningRequest.ValidateRequestSignature();
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
            AsymmetricSignedPublicKey.RootTrustAsync = (id, ct) => Task.FromResult(id.SequenceEqual(signedRootPublicKey.PublicKey.ID));
            AsymmetricSignedPublicKey.SignedPublicKeyStoreAsync = async (id, ct) =>
            {
                await Task.Yield();
                if (id.SequenceEqual(signedRootPublicKey.PublicKey.ID)) return signedRootPublicKey;
                if (id.SequenceEqual(signedPublicKey.PublicKey.ID)) return signedPublicKey;
                return null;
            };
            // Validate the signed key
            signedPublicKey.Validate();
            await signedPublicKey.ValidateAsync();
            // Test key revocation
            AsymmetricSignedPublicKey.SignedPublicKeyRevocation = (id) => true;
            AsymmetricSignedPublicKey.SignedPublicKeyRevocationAsync = (id, ct) => Task.FromResult(true);
            Assert.IsFalse(signedPublicKey.Validate(throwOnError: false));
            Assert.IsFalse(await signedPublicKey.ValidateAsync(throwOnError: false));
            Assert.ThrowsException<CryptographicException>(() => signedPublicKey.Validate());
            await Assert.ThrowsExceptionAsync<CryptographicException>(async () => await signedPublicKey.ValidateAsync());
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
    }
}
