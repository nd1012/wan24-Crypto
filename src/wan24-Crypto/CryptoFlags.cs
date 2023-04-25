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
        /// MAC algorithm included?
        /// </summary>
        MacAlgorithmIncluded = 1 << 8,
        /// <summary>
        /// KDF algorithm included?
        /// </summary>
        KdfAlgorithmIncluded = 1 << 9,
        /// <summary>
        /// Key exchange data included?
        /// </summary>
        KeyExchangeDataIncluded = 1 << 10,
        /// <summary>
        /// Payload included
        /// </summary>
        PayloadIncluded = 1 << 11,
        /// <summary>
        /// Time included?
        /// </summary>
        TimeIncluded = 1 << 12,
        /// <summary>
        /// Is the MAC forced to cover all data?
        /// </summary>
        ForceMacCoverWhole = 1 << 13,
        /// <summary>
        /// Require a counter MAC
        /// </summary>
        RequireCounterMac = 1 << 14,
        /// <summary>
        /// Require an asymmetric counter algorithm
        /// </summary>
        RequireAsymmetricCounterAlgorithm = 1 << 15,
        /// <summary>
        /// Require a counter KDF algorithm
        /// </summary>
        RequireCounterKdfAlgorithm = 1 << 16,
        /// <summary>
        /// All flags
        /// </summary>
        FLAGS = HeaderVersionIncluded |
            SerializerVersionIncluded |
            MacIncluded |
            MacAlgorithmIncluded |
            Compressed |
            MacAlgorithmIncluded |
            KdfAlgorithmIncluded |
            KeyExchangeDataIncluded |
            PayloadIncluded |
            TimeIncluded |
            ForceMacCoverWhole |
            RequireCounterMac |
            RequireAsymmetricCounterAlgorithm |
            RequireCounterKdfAlgorithm
    }
}
