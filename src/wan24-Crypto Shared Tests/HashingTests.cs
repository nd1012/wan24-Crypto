using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace wan24.Crypto.Tests
{
    public static class HashingTests
    {
        public static async Task TestAllAlgorithms()
        {
            Assert.IsFalse(HashHelper.Algorithms.IsEmpty);
            foreach (string name in HashHelper.Algorithms.Keys)
            {
                AlgorithmTests(name);
                await AlgorithmTestsAsync(name);
            }
        }

        public static void AlgorithmTests(string name)
        {
            Console.WriteLine($"Synchronous hash {name} tests");
            HashAlgorithmBase algo = HashHelper.GetAlgorithm(name);
            using MemoryStream ms = new(TestData.Data);
            byte[] streamHash = algo.Hash(ms),
                memoryHash = TestData.Data.Hash(new()
                {
                    HashAlgorithm = name
                });
            Assert.AreEqual(algo.HashLength, streamHash.Length);
            Assert.AreEqual(algo.HashLength, memoryHash.Length);
            Assert.IsTrue(streamHash.SequenceEqual(memoryHash));
            using MemoryStream temp = new();
            HashStreams hashStreams = algo.GetHashStream(temp, options: new()
            {
                LeaveOpen = true
            });
            try
            {
                ms.Position = 0;
                ms.CopyTo(hashStreams.Stream);
                hashStreams.Stream.FlushFinalBlock();
                streamHash = hashStreams.Transform.Hash!;
                Assert.IsNotNull(streamHash);
                Assert.AreEqual(algo.HashLength, streamHash.Length);
                Assert.IsTrue(streamHash.SequenceEqual(memoryHash));
                Assert.AreEqual(TestData.Data.LongLength, temp.Length);
                byte[] data = new byte[temp.Length];
                temp.Position = 0;
                Assert.AreEqual(data.Length, temp.Read(data));
                Assert.IsTrue(TestData.Data.SequenceEqual(data));
            }
            finally
            {
                hashStreams.Dispose();
            }
            temp.SetLength(0);
            hashStreams = algo.GetHashStream(temp, options: new()
            {
                LeaveOpen = false
            });
            try
            {
                ms.Position = 0;
                ms.CopyTo(hashStreams.Stream);
                hashStreams.Stream.FlushFinalBlock();
                streamHash = hashStreams.Transform.Hash!;
                Assert.IsNotNull(streamHash);
                Assert.AreEqual(algo.HashLength, streamHash.Length);
                Assert.IsTrue(streamHash.SequenceEqual(memoryHash));
                Assert.AreEqual(TestData.Data.LongLength, temp.Length);
                hashStreams.Dispose();
                try
                {
                    temp.Position = 0;
                }
                catch (ObjectDisposedException)
                {
                }
            }
            finally
            {
                hashStreams.Dispose();
            }
        }

        public static async Task AlgorithmTestsAsync(string name)
        {
            Console.WriteLine($"Asynchronous hash {name} tests");
            HashAlgorithmBase algo = HashHelper.GetAlgorithm(name);
            using MemoryStream ms = new(TestData.Data);
            byte[] streamHash = await algo.HashAsync(ms);
            Assert.AreEqual(algo.HashLength, streamHash.Length);
            Assert.IsTrue(streamHash.SequenceEqual(TestData.Data.Hash(new()
            {
                HashAlgorithm = name
            })));
        }
    }
}
