﻿using wan24.Core;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class PasswordHelper_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            char[] pwd = PasswordHelper.GeneratePassword();
            Logging.WriteInfo($"Generated password: {new string(pwd)}");
            Assert.AreEqual(PasswordHelper.DefaultLength, pwd.Length);
            Assert.AreEqual(PasswordOptions.None, PasswordHelper.CheckPassword(pwd, PasswordHelper.DefaultOptions));
        }
    }
}
