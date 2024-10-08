﻿using System.Security.Cryptography;
using wan24.Crypto;
using wan24.Crypto.Tests;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Mac_Tests : TestBase
    {
        [TestMethod]
        public async Task All_Tests() => await MacTests.TestAllAlgorithms();

        [TestMethod]
        public void MacHelper_Tests()
        {
            Assert.AreEqual(HMACSHA3_512.IsSupported ? MacHmacSha3_512Algorithm.ALGORITHM_NAME : MacHmacSha512Algorithm.ALGORITHM_NAME, MacHelper.DefaultAlgorithm.Name);
            Assert.AreEqual(MacHelper.DefaultAlgorithm.MacLength, TestData.Data.Hash().Length);
            Assert.AreEqual(MacHelper.DefaultAlgorithm, MacHelper.GetAlgorithm(MacHelper.DefaultAlgorithm.Name));
            Assert.AreEqual(MacHelper.DefaultAlgorithm, MacHelper.GetAlgorithm(MacHelper.DefaultAlgorithm.Value));
        }
    }
}
