﻿namespace wan24.Crypto
{
    /// <summary>
    /// Key exchange private key
    /// </summary>
    public interface IKeyExchangePrivateKey : IAsymmetricPrivateKey
    {
        /// <summary>
        /// Get key exchange data
        /// </summary>
        /// <param name="publicKey">Peer public key</param>
        /// <param name="options">Options</param>
        /// <returns>Derived key and key exchange data</returns>
        (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData(IAsymmetricPublicKey? publicKey = null, CryptoOptions? options = null);
        /// <summary>
        /// Get the derived key from received key exchange data
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <returns>Derived key</returns>
        byte[] DeriveKey(byte[] keyExchangeData);
    }
}
