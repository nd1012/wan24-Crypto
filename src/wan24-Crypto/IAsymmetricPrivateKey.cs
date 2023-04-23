namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric private key
    /// </summary>
    public interface IAsymmetricPrivateKey : IAsymmetricKey
    {
        /// <summary>
        /// Public key (don't dispose - will be disposed, when the private key instance is disposing!)
        /// </summary>
        IAsymmetricPublicKey PublicKey { get; }
        /// <summary>
        /// Get a copy
        /// </summary>
        /// <returns>Copy</returns>
        IAsymmetricPrivateKey GetCopy();
        /// <summary>
        /// Sign data
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="purpose">Purpose</param>
        /// <param name="options">Options</param>
        /// <returns>Signature</returns>
        SignatureContainer SignData(byte[] data, string? purpose = null, CryptoOptions? options = null);
        /// <summary>
        /// Sign data
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="purpose">Purpose</param>
        /// <param name="options">Options</param>
        /// <returns>Signature</returns>
        SignatureContainer SignData(Stream data, string? purpose = null, CryptoOptions? options = null);
        /// <summary>
        /// Sign data
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="purpose">Purpose</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Signature</returns>
        Task<SignatureContainer> SignDataAsync(Stream data, string? purpose = null, CryptoOptions? options = null, CancellationToken cancellationToken = default);
        /// <summary>
        /// Sign a hash
        /// </summary>
        /// <param name="hash">Hash</param>
        /// <param name="purpose">Purpose</param>
        /// <param name="options">Options</param>
        /// <returns>Signature</returns>
        SignatureContainer SignHash(byte[] hash, string? purpose = null, CryptoOptions? options = null);
        /// <summary>
        /// Sign a hash
        /// </summary>
        /// <param name="hash">Hash</param>
        /// <returns>Signature (RFC 3279 DER sequence)</returns>
        byte[] SignHashRaw(byte[] hash);
        /// <summary>
        /// Get key exchange data
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Key exchange data</returns>
        byte[] GetKeyExchangeData(CryptoOptions? options = null);
        /// <summary>
        /// Get the derived key from received key exchange data
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <returns>Derived key</returns>
        byte[] DeriveKey(byte[] keyExchangeData);
    }
}
