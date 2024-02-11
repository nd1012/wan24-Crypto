using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;

namespace wan24.Crypto.Tests
{
    public static class MacTests
    {
        public static async Task TestAllAlgorithms()
        {
            Assert.IsFalse(MacHelper.Algorithms.IsEmpty);
            int done = 0;
            foreach (string name in MacHelper.Algorithms.Keys)
            {
                AlgorithmTests(name);
                await AlgorithmTestsAsync(name);
                done += 2;
            }
            Console.WriteLine($"{done} tests done");
        }

        public static void AlgorithmTests(string name)
        {
            Console.WriteLine($"Synchronous MAC {name} tests");
            Stopwatch sw = Stopwatch.StartNew();
            MacAlgorithmBase algo = MacHelper.GetAlgorithm(name);
            using MemoryStream ms = new(TestData.Data);
            Console.WriteLine("\tStream and memory test");
            byte[] streamMac = algo.Mac(ms, TestData.Key),
                memoryMac = TestData.Data.Mac(TestData.Key, new()
                {
                    MacAlgorithm = name
                });
            Assert.AreEqual(algo.MacLength, streamMac.Length);
            Assert.AreEqual(algo.MacLength, memoryMac.Length);
            Assert.IsTrue(streamMac.SequenceEqual(memoryMac));
            using MemoryStream temp = new();
            Console.WriteLine("\tMAC streams test (leave open)");
            MacStreams macStreams = algo.GetMacStream(TestData.Key, temp, options: new()
            {
                LeaveOpen = true
            });
            try
            {
                ms.Position = 0;
                ms.CopyTo(macStreams.Stream);
                macStreams.Stream.FlushFinalBlock();
                streamMac = macStreams.Transform.Hash!;
                Assert.IsNotNull(streamMac);
                Assert.AreEqual(algo.MacLength, streamMac.Length);
                Assert.IsTrue(streamMac.SequenceEqual(memoryMac));
                Assert.AreEqual(TestData.Data.LongLength, temp.Length);
                byte[] data = new byte[temp.Length];
                temp.Position = 0;
                Assert.AreEqual(data.Length, temp.Read(data));
                Assert.IsTrue(TestData.Data.SequenceEqual(data));
            }
            finally
            {
                macStreams.Dispose();
            }
            temp.SetLength(0);
            Console.WriteLine("\tMAC streams test");
            macStreams = algo.GetMacStream(TestData.Key, temp, options: new()
            {
                LeaveOpen = false
            });
            try
            {
                ms.Position = 0;
                ms.CopyTo(macStreams.Stream);
                macStreams.Stream.FlushFinalBlock();
                streamMac = macStreams.Transform.Hash!;
                Assert.IsNotNull(streamMac);
                Assert.AreEqual(algo.MacLength, streamMac.Length);
                Assert.IsTrue(streamMac.SequenceEqual(memoryMac));
                Assert.AreEqual(TestData.Data.LongLength, temp.Length);
                macStreams.Dispose();
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
                macStreams.Dispose();
            }
            Console.WriteLine($"\tRuntime {sw.Elapsed}");
        }

        public static async Task AlgorithmTestsAsync(string name)
        {
            Console.WriteLine($"Asynchronous MAC {name} tests");
            Stopwatch sw = Stopwatch.StartNew();
            MacAlgorithmBase algo = MacHelper.GetAlgorithm(name);
            using MemoryStream ms = new(TestData.Data);
            byte[] streamMac = await algo.MacAsync(ms, TestData.Key);
            Assert.AreEqual(algo.MacLength, streamMac.Length);
            Assert.IsTrue(streamMac.SequenceEqual(TestData.Data.Mac(TestData.Key, new()
            {
                MacAlgorithm = name
            })));
            Console.WriteLine($"\tRuntime {sw.Elapsed}");
        }
    }
}
