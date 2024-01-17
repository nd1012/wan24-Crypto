using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using wan24.Core;
using wan24.Crypto;
using wan24.ObjectValidation;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class A_Initialization
    {
        public static ILoggerFactory LoggerFactory { get; private set; } = null!;

        [AssemblyInitialize]
        public static void Init(TestContext tc)
        {
            LoggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(b => b.AddConsole());
            Logging.Logger = LoggerFactory.CreateLogger("Tests");
            ValidateObject.Logger = (message) => Logging.WriteDebug(message);
            TypeHelper.Instance.ScanAssemblies(typeof(A_Initialization).Assembly);
            wan24.Core.Bootstrap.Async().Wait();
            wan24.Crypto.Bootstrap.Boot();
            DisposableBase.CreateStackInfo = true;
            ErrorHandling.ErrorHandler = (info) =>
            {
                if(info.Exception is StackInfoException six) Logging.WriteError(six.StackInfo.Stack);
            };
            ValidateObject.Logger("wan24-Crypto Tests initialized");
            // Disable algorithms which are not supported in this platform
            if (!SHA3_512.IsSupported)
            {
                // SHA3 hash
                HashHelper.DefaultAlgorithm = HashSha512Algorithm.Instance;
                HashHelper.Algorithms.TryRemove(HashSha3_256Algorithm.ALGORITHM_NAME, out _);
                HashHelper.Algorithms.TryRemove(HashSha3_384Algorithm.ALGORITHM_NAME, out _);
                HashHelper.Algorithms.TryRemove(HashSha3_512Algorithm.ALGORITHM_NAME, out _);
                HashHelper.Algorithms.TryRemove(HashShake128Algorithm.ALGORITHM_NAME, out _);
                HashHelper.Algorithms.TryRemove(HashShake256Algorithm.ALGORITHM_NAME, out _);
                // SHA3 HMAC
                MacHelper.DefaultAlgorithm = MacHmacSha512Algorithm.Instance;
                MacHelper.Algorithms.TryRemove(MacHmacSha3_256Algorithm.ALGORITHM_NAME, out _);
                MacHelper.Algorithms.TryRemove(MacHmacSha3_384Algorithm.ALGORITHM_NAME, out _);
                MacHelper.Algorithms.TryRemove(MacHmacSha3_512Algorithm.ALGORITHM_NAME, out _);
                // Pake default options
                Pake.DefaultOptions = Pake.DefaultOptions
                    .WithHashAlgorithm(HashSha512Algorithm.ALGORITHM_NAME)
                    .WithMac(MacHmacSha512Algorithm.ALGORITHM_NAME, included: false);
                // KDF (don't use SHA3 and remove SP800-108)
                KdfHelper.Algorithms.TryRemove(KdfSp800_108HmacCtrKbKdfAlgorithm.ALGORITHM_NAME, out _);
                KdfPbKdf2Options.DefaultHashAlgorithm = HashSha384Algorithm.ALGORITHM_NAME;
            }
        }
    }
}
