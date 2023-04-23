namespace wan24.Crypto
{
    /// <summary>
    /// Signature private key
    /// </summary>
    public interface ISignaturePrivateKey : IAsymmetricPrivateKey
    {
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
    }
}
