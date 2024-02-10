namespace wan24.Crypto
{
    /// <summary>
    /// Key exchange private key
    /// </summary>
    public interface IKeyExchangePrivateKey : IAsymmetricPrivateKey, IKeyExchange
    {
        /// <summary>
        /// Get key exchange data
        /// </summary>
        /// <param name="publicKey">Peer public key</param>
        /// <param name="options">Options</param>
        /// <returns>Derived key and key exchange data</returns>
        (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null);
        /// <summary>
        /// Get the derived key from a public key
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <returns>Derived key</returns>
        byte[] DeriveKey(IAsymmetricPublicKey publicKey);
    }
}
