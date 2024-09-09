using wan24.Core;
using wan24.Crypto;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class PasswordHelper_Tests : TestBase
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
