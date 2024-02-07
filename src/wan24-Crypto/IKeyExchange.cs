namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an object which can be used to perform a key exchange
    /// </summary>
    public interface IKeyExchange
    {
        /// <summary>
        /// Get a key and the key exchange data
        /// </summary>
        /// <returns>Key and key exchange data</returns>
        public (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData();
        /// <summary>
        /// Derive a key from key exchange data
        /// </summary>
        /// <param name="keyExchangeData">Key exchange data</param>
        /// <returns>Derived key</returns>
        public byte[] DeriveKey(byte[] keyExchangeData);
    }
}
