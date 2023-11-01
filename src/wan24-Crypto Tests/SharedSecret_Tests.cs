using wan24.Core;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class SharedSecret_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            CryptoOptions options = MacHelper.GetDefaultOptions();
            MacAlgorithmBase algo = MacHelper.GetAlgorithm(options.MacAlgorithm!);
            byte[] token = RND.GetBytes(123),
                key = RND.GetBytes(345),
                remoteSecret = RND.GetBytes(algo.MacLength),
                finalSecret,
                finalSecret2;
            using (SharedSecret tss = new(token.CloneArray(), key.CloneArray()))
            {
                tss.ProtectRemoteSecret(remoteSecret);
                // tss.Secret.Array and remoteSecret need to be sent to the remote key storage
                finalSecret = tss.DeriveFinalSecretAndDispose(remoteSecret.CloneArray());
            }
            using (SharedSecret tss = new(token, key))
                // tss.Secret.Array must be sent to the remote key storage for receiving remoteSecret
                finalSecret2 = tss.DeriveFinalSecretAndDispose(remoteSecret);
            Assert.IsTrue(finalSecret.SequenceEqual(finalSecret2));
        }
    }
}
