using System.Security.Cryptography;

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
            => algo switch
            {
                ECDiffieHellman => AsymmetricHelper.GetAlgorithm(AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME),
                ECDsa => AsymmetricHelper.GetAlgorithm(AsymmetricEcDsaAlgorithm.ALGORITHM_NAME),
                _ => null
            };
    }
}
