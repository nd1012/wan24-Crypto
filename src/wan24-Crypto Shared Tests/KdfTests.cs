using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;

namespace wan24.Crypto.Tests
{
    public static class KdfTests
    {
        public static void TestAllAlgorithms()
        {
            Assert.IsFalse(KdfHelper.Algorithms.IsEmpty);
            int done = 0;
            foreach (string name in KdfHelper.Algorithms.Keys)
            {
                AlgorithmTests(name);
                done++;
            }
            Console.WriteLine($"{done} tests done");
        }

        public static void AlgorithmTests(string name)
        {
            Console.WriteLine($"KDF algorithm {name} tests");
            Stopwatch sw = Stopwatch.StartNew();
            KdfAlgorithmBase algo = KdfHelper.GetAlgorithm(name);
            (byte[] stretched, byte[] salt) = algo.Stretch(TestData.Key, 64);
            Assert.AreEqual(64, stretched.Length);
            Assert.AreEqual(algo.SaltLength, salt.Length);
            (byte[] stretched2, _) = algo.Stretch(TestData.Key, 64, salt);
            Assert.IsTrue(stretched.SequenceEqual(stretched2));
            Console.WriteLine($"\tRuntime {sw.Elapsed}");
        }
    }
}
