namespace wan24.Crypto.Tests
{
    public static class KdfTests
    {
        public static void TestAllAlgorithms()
        {
            Assert.IsTrue(KdfHelper.Algorithms.Count > 0);
            foreach (string name in KdfHelper.Algorithms.Keys) AlgorithmTests(name);
        }

        public static void AlgorithmTests(string name)
        {
            Console.WriteLine($"KDF algorithm {name} tests");
            KdfAlgorithmBase algo = KdfHelper.GetAlgorithm(name);
            (byte[] stretched, byte[] salt) = algo.Stretch(TestData.Key, 64);
            Assert.AreEqual(64, stretched.Length);
            Assert.AreEqual(algo.SaltLength, salt.Length);
            (byte[] stretched2, _) = algo.Stretch(TestData.Key, 64, salt);
            Assert.IsTrue(stretched.SequenceEqual(stretched2));
        }
    }
}
