using System.Security.Cryptography;

namespace wan24.Crypto.Tests
{
    public static class SharedTests
    {
        public static void Initialize()
        {
            // Disable algorithms which are not supported in this platform
            if (!Shake128.IsSupported)
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
                    .WithMac(MacHmacSha512Algorithm.ALGORITHM_NAME, included: false);
                Pake.DefaultCryptoOptions = Pake.DefaultCryptoOptions
                    .WithMac(MacHmacSha512Algorithm.ALGORITHM_NAME, included: false);
                // KDF (don't use SHA3 and remove SP800-108)
                KdfHelper.Algorithms.TryRemove(KdfSp800_108HmacCtrKbKdfAlgorithm.ALGORITHM_NAME, out _);
                KdfPbKdf2Options.DefaultHashAlgorithm = HashSha384Algorithm.ALGORITHM_NAME;
            }
        }
    }
}
