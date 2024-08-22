using wan24.Core;
using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class A_Initialization
    {
        [AssemblyInitialize]
        public static void Init(TestContext tc)
        {
            wan24.Tests.TestsInitialization.Init(tc);
            wan24.Crypto.Bootstrap.Boot();
            SharedTests.Initialize();
            Logging.WriteInfo("wan24-Crypto Tests initialized");
        }
    }
}
