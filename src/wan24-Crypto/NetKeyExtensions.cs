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

        /// <summary>
        /// Get a private key instance
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>Private key (don't forget to dispose!)</returns>
        public static IAsymmetricPrivateKey GetAsymmetricPrivateKey(this AsymmetricAlgorithm algo)
        {
            IAsymmetricAlgorithm aa = algo.GetAsymmetricAlgorithm() ?? throw new ArgumentException("Unsupported algorithm", nameof(algo));
            if (aa is AsymmetricEcDiffieHellmanAlgorithm) return new AsymmetricEcDiffieHellmanPrivateKey(algo.ExportPkcs8PrivateKey());
            if (aa is AsymmetricEcDsaAlgorithm) return new AsymmetricEcDsaPrivateKey(algo.ExportPkcs8PrivateKey());
            throw new NotImplementedException($"Algorithm {aa.Name} wasn't implemented (this is a bug)");
        }

        /// <summary>
        /// Get a public key instance
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <returns>Public key (don't forget to dispose!)</returns>
        public static IAsymmetricPublicKey GetAsymmetricPublicKey(this AsymmetricAlgorithm algo)
        {
            IAsymmetricAlgorithm aa = algo.GetAsymmetricAlgorithm() ?? throw new ArgumentException("Unsupported algorithm", nameof(algo));
            if (aa is AsymmetricEcDiffieHellmanAlgorithm) return new AsymmetricEcDiffieHellmanPublicKey(algo.ExportSubjectPublicKeyInfo());
            if (aa is AsymmetricEcDsaAlgorithm) return new AsymmetricEcDsaPublicKey(algo.ExportSubjectPublicKeyInfo());
            throw new NotImplementedException($"Algorithm {aa.Name} wasn't implemented (this is a bug)");
        }
    }
}
