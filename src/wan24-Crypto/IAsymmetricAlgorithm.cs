using System.Collections.ObjectModel;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric algorithm
    /// </summary>
    public interface IAsymmetricAlgorithm : ICryptoAlgorithm
    {
        /// <summary>
        /// Default options
        /// </summary>
        CryptoOptions DefaultOptions { get; }
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
        /// Allowed key sizes in bits
        /// </summary>
        ReadOnlyCollection<int> AllowedKeySizes { get; }
        /// <summary>
        /// Default key size in bits
        /// </summary>
        int DefaultKeySize { get; }
        /// <summary>
        /// Create a new key pair
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Private key</returns>
        IAsymmetricPrivateKey CreateKeyPair(CryptoOptions? options = null);
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
        /// Get the derived key from received key exchange data
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <param name="options">Options</param>
        /// <returns>Derived key</returns>
        byte[] DeriveKey(byte[] keyExchangeData, CryptoOptions? options = null);
    }
}
