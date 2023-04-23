using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Kdf_Tests
    {
        public static readonly byte[] Key = new byte[] { 1, 2, 3 };

        [TestMethod]
        public void General_Tests()
        {
            Assert.IsTrue(KdfHelper.Algorithms.Count > 0);
            foreach (string name in KdfHelper.Algorithms.Keys) KdfAlgo_Tests(name);
        }

        [TestMethod]
        public void KdfHelper_Tests()
        {
            Assert.AreEqual(KdfPbKdf2Algorithm.ALGORITHM_NAME, KdfHelper.DefaultAlgorithm.Name);
            Assert.AreEqual(KdfHelper.DefaultAlgorithm.SaltLength, Key.Stretch(64).Salt.Length);
            Assert.AreEqual(KdfHelper.DefaultAlgorithm, KdfHelper.GetAlgorithm(KdfHelper.DefaultAlgorithm.Name));
            Assert.AreEqual(KdfHelper.DefaultAlgorithm, KdfHelper.GetAlgorithm(KdfHelper.DefaultAlgorithm.Value));
            Assert.AreEqual(KdfHelper.DefaultAlgorithm.Name, KdfHelper.GetAlgorithmName(KdfHelper.DefaultAlgorithm.Value));
            Assert.AreEqual(KdfHelper.DefaultAlgorithm.Value, KdfHelper.GetAlgorithmValue(KdfHelper.DefaultAlgorithm.Name));
        }

        public void KdfAlgo_Tests(string name)
        {
            Console.WriteLine($"KDF algorithm {name} tests");
            KdfAlgorithmBase algo = KdfHelper.GetAlgorithm(name);
            (byte[] stretched, byte[] salt) = algo.Stretch(Key, 64);
            Assert.AreEqual(64, stretched.Length);
            Assert.AreEqual(algo.SaltLength, salt.Length);
            (byte[] stretched2, _) = algo.Stretch(Key, 64, salt);
            Assert.IsTrue(stretched.SequenceEqual(stretched2));
        }
    }
}
