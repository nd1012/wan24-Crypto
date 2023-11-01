using wan24.Core;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class MacSignature_Tests
    {
        [TestMethod]
        public void General_Test()
        {
            byte[] key = RND.GetBytes(64);
            using MacSignature signer = new(key, isSharedKey: false);
            byte[] signature = signer.Sign(key);
            Assert.IsTrue(MacSignature.AuthenticateSignedData(key, signature));
            Assert.IsTrue(signer.Validate(key, signature));
            using MacSignature signer2 = new(signer.SharedKey.Array.CloneArray(), isSharedKey: true);
            Assert.IsTrue(signer2.Validate(key, signature));
        }

        [TestMethod]
        public async Task GeneralAsync_Test()
        {
            byte[] key = await RND.GetBytesAsync(64);
            using MacSignature signer = new(key, isSharedKey: false);
            byte[] signature = await signer.SignAsync(key);
            Assert.IsTrue(signer.Validate(key, signature));
            using MacSignature signer2 = new(signer.SharedKey.Array.CloneArray(), isSharedKey: true);
            Assert.IsTrue(signer2.Validate(key, signature));
        }
    }
}
