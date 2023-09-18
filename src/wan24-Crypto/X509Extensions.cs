using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace wan24.Crypto
{
    /// <summary>
    /// X509 extensions
    /// </summary>
    public static class X509Extensions
    {
        /// <summary>
        /// Get the asymmetric algorithm
        /// </summary>
        /// <param name="cert">Certificate</param>
        /// <returns>Algorithm or <see langword="null"/>, if the key algorithm isn't supported</returns>
        public static IAsymmetricAlgorithm? GetAsymmetricAlgorithm(this X509Certificate2 cert)
        {
            if (cert.PublicKey.GetECDiffieHellmanPublicKey() is not null) return AsymmetricHelper.GetAlgorithm(AsymmetricEcDiffieHellmanAlgorithm.ALGORITHM_NAME);
            if (cert.PublicKey.GetECDsaPublicKey() is not null) return AsymmetricHelper.GetAlgorithm(AsymmetricEcDsaAlgorithm.ALGORITHM_NAME);
            return null;
        }

        /// <summary>
        /// Get the asymmetric public key
        /// </summary>
        /// <param name="cert">Certificate</param>
        /// <returns>Public key (don't forget to dispose!) or <see langword="null"/>, if the key algorithm isn't supported</returns>
        public static IAsymmetricPublicKey? GetAsymmetricPublicKey(this X509Certificate2 cert)
        {
            if (cert.PublicKey.GetECDiffieHellmanPublicKey() is ECDiffieHellman ecDh) return new AsymmetricEcDiffieHellmanPublicKey(ecDh.ExportSubjectPublicKeyInfo());
            else if (cert.PublicKey.GetECDsaPublicKey() is ECDsa ecDsa) return new AsymmetricEcDsaPublicKey(ecDsa.ExportSubjectPublicKeyInfo());
            return null;
        }

        /// <summary>
        /// Get the asymmetric private key
        /// </summary>
        /// <param name="cert">Certificate</param>
        /// <returns>Private key (don't forget to dispose!) or <see langword="null"/>, if the key algorithm isn't supported</returns>
        public static IAsymmetricPrivateKey? GetAsymmetricPrivateKey(this X509Certificate2 cert)
        {
            if (!cert.HasPrivateKey) throw new ArgumentException("No private key", nameof(cert));
            if (cert.GetECDiffieHellmanPrivateKey() is ECDiffieHellman ecDh) return new AsymmetricEcDiffieHellmanPrivateKey(ecDh.ExportPkcs8PrivateKey());
            else if (cert.GetECDsaPrivateKey() is ECDsa ecDsa) return new AsymmetricEcDsaPrivateKey(ecDsa.ExportPkcs8PrivateKey());
            return null;
        }
    }
}
