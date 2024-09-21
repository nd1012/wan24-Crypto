using System.Collections.Frozen;
using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric algorithm
    /// </summary>
    public interface IAsymmetricAlgorithm : ICryptoAlgorithm, ILimitKeyUsageCount
    {
        /// <summary>
        /// Default options
        /// </summary>
        CryptoOptions DefaultOptions { get; }
        /// <summary>
        /// Default algorithm options
        /// </summary>
        string? DefaultAlgorithmOptions { get; }
        /// <summary>
        /// Key usages
        /// </summary>
        AsymmetricAlgorithmUsages Usages { get; }
        /// <summary>
        /// Can exchange a key?
        /// </summary>
        bool CanExchangeKey { get; }
        /// <summary>
        /// Can sign?
        /// </summary>
        bool CanSign { get; }
        /// <summary>
        /// Is an elliptic curve algorithm?
        /// </summary>
        bool IsEllipticCurveAlgorithm { get; }
        /// <summary>
        /// Is the public key exported in a standard format?
        /// </summary>
        bool IsPublicKeyStandardFormat { get; }
        /// <summary>
        /// Allowed key sizes in bits
        /// </summary>
        FrozenSet<int> AllowedKeySizes { get; }
        /// <summary>
        /// Default key size in bits
        /// </summary>
        int DefaultKeySize { get; }
        /// <summary>
        /// Private key type
        /// </summary>
        Type PrivateKeyType { get; }
        /// <summary>
        /// Public key type
        /// </summary>
        Type PublicKeyType { get; }
        /// <summary>
        /// Was this allogithm denied (still usable for key derivation and signature validation, but not for key exchange initialization and signature)?
        /// </summary>
        bool IsDenied { get; }
        /// <summary>
        /// Key pool (key is the key size, value the key pool)
        /// </summary>
        Dictionary<int, IAsymmetricKeyPool>? KeyPool { get; set; }
        /// <summary>
        /// Ensure that the given options include the default options for this algorithm
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        CryptoOptions EnsureDefaultOptions(CryptoOptions? options = null);
        /// <summary>
        /// Create a new key pair
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Private key</returns>
        IAsymmetricPrivateKey CreateKeyPair(CryptoOptions? options = null);
        /// <summary>
        /// Create a new key pair
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Private key</returns>
        Task<IAsymmetricPrivateKey> CreateKeyPairAsync(CryptoOptions? options = null, CancellationToken cancellationToken = default);
        /// <summary>
        /// Deserialize a public key from a stream
        /// </summary>
        /// <param name="keyData">Key data</param>
        /// <returns>Public key</returns>
        IAsymmetricPublicKey DeserializePublicKey(byte[] keyData);
        /// <summary>
        /// Deserialize a private key from a stream
        /// </summary>
        /// <param name="keyData">Key data</param>
        /// <returns>Private key</returns>
        IAsymmetricPrivateKey DeserializePrivateKey(byte[] keyData);
        /// <summary>
        /// Get the derived PFS key from received key exchange data
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <param name="options">Options</param>
        /// <returns>Derived PFS key</returns>
        byte[] DeriveKey(byte[] keyExchangeData, CryptoOptions? options = null);
        /// <summary>
        /// Determine if this asymmetric algorithm can handle a .NET asymmetric algorithm
        /// </summary>
        /// <param name="algo">Asymmetric algorithm</param>
        /// <returns>If this asymmetric algorithm can handle the .NET asymmetric algorithm</returns>
        bool CanHandleNetAlgorithm(AsymmetricAlgorithm algo);
    }
}
