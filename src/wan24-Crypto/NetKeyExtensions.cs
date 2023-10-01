using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// .NET asymmetric keys extensions
    /// </summary>
    public static class NetKeyExtensions
    {

        /// <summary>
        /// Get the asymmetric algorithm
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>Algorithm</returns>
        public static IAsymmetricAlgorithm? GetAsymmetricAlgorithm(this AsymmetricAlgorithm algo)
            => AsymmetricHelper.Algorithms.Values.FirstOrDefault(a => a.CanHandleNetAlgorithm(algo));

        /// <summary>
        /// Get a private key instance
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>Private key (don't forget to dispose!)</returns>
        public static IAsymmetricPrivateKey GetAsymmetricPrivateKey(this AsymmetricAlgorithm algo)
        {
            IAsymmetricAlgorithm aa = algo.GetAsymmetricAlgorithm() ?? throw new ArgumentException("Unsupported algorithm", nameof(algo));
            return (IAsymmetricPrivateKey)aa.PrivateKeyType.ConstructAuto(usePrivate: false, algo);
        }

        /// <summary>
        /// Get a public key instance
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>Public key (don't forget to dispose!)</returns>
        public static IAsymmetricPublicKey GetAsymmetricPublicKey(this AsymmetricAlgorithm algo)
        {
            IAsymmetricAlgorithm aa = algo.GetAsymmetricAlgorithm() ?? throw new ArgumentException("Unsupported algorithm", nameof(algo));
            return (IAsymmetricPublicKey)aa.PublicKeyType.ConstructAuto(usePrivate: false, algo);
        }
    }
}
