namespace wan24.Crypto
{
    /// <summary>
    /// Crypto flags
    /// </summary>
    [Flags]
    public enum CryptoFlags : int
    {
        /// <summary>
        /// Crypto header data structure version 1
        /// </summary>
        Version1 = 1,
        /// <summary>
        /// Header version included?
        /// </summary>
        HeaderVersionIncluded = 1 << 4,
        /// <summary>
        /// Serializer version included?
        /// </summary>
        SerializerVersionIncluded = 1 << 5,
        /// <summary>
        /// MAC included?
        /// </summary>
        MacIncluded = 1 << 6,
        /// <summary>
        /// Compressed?
        /// </summary>
        Compressed = 1 << 7,
        /// <summary>
        /// Crypto algorithm included?
        /// </summary>
        AlgorithmIncluded = 1 << 8,
        /// <summary>
        /// MAC algorithm included?
        /// </summary>
        MacAlgorithmIncluded = 1 << 9,
        /// <summary>
        /// KDF algorithm included?
        /// </summary>
        KdfAlgorithmIncluded = 1 << 10,
        /// <summary>
        /// Asymmetric algorithm included (for the key exchange data)?
        /// </summary>
        AsymmetricAlgorithmIncluded = 1 << 11,
        /// <summary>
        /// MAC algorithm included?
        /// </summary>
        CounterMacAlgorithmIncluded = 1 << 12,
        /// <summary>
        /// KDF algorithm included?
        /// </summary>
        CounterKdfAlgorithmIncluded = 1 << 13,
        /// <summary>
        /// Asymmetric algorithm included (for the key exchange data)?
        /// </summary>
        AsymmetricCounterAlgorithmIncluded = 1 << 14,
        /// <summary>
        /// Key exchange data included?
        /// </summary>
        KeyExchangeDataIncluded = 1 << 15,
        /// <summary>
        /// Payload included
        /// </summary>
        PayloadIncluded = 1 << 16,
        /// <summary>
        /// Time included?
        /// </summary>
        TimeIncluded = 1 << 17,
        /// <summary>
        /// Is the MAC forced to cover all data?
        /// </summary>
        ForceMacCoverWhole = 1 << 18,
        /// <summary>
        /// All flags
        /// </summary>
        FLAGS = HeaderVersionIncluded |
            SerializerVersionIncluded | 
            MacIncluded | 
            MacAlgorithmIncluded | 
            Compressed | 
            AlgorithmIncluded | 
            MacAlgorithmIncluded | 
            KdfAlgorithmIncluded | 
            AsymmetricAlgorithmIncluded |
            CounterMacAlgorithmIncluded |
            CounterKdfAlgorithmIncluded |
            AsymmetricCounterAlgorithmIncluded |
            KeyExchangeDataIncluded | 
            PayloadIncluded | 
            TimeIncluded
    }
}
