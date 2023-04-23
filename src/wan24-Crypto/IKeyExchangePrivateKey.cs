namespace wan24.Crypto
{
    /// <summary>
    /// Key exchange private key
    /// </summary>
    public interface IKeyExchangePrivateKey : IAsymmetricPrivateKey
    {
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
