using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto flags
    /// </summary>
    [Flags]
    public enum CryptoFlags : int
    {
        /// <summary>
        /// Latest crypto header data structure version
        /// </summary>
        [DisplayText("Latest crypto header data structure version")]
        LatestVersion = Version1,
#pragma warning disable CA1069 // Double constant value
        /// <summary>
        /// Crypto header data structure version 1
        /// </summary>
        [DisplayText("Crypto header data structure version 1")]
        Version1 = 1,
#pragma warning restore CA1069 // Double constant value
        /// <summary>
        /// Header version included?
        /// </summary>
        [DisplayText("Header version included?")]
        HeaderVersionIncluded = 1 << 4,
        /// <summary>
        /// Serializer version included?
        /// </summary>
        [DisplayText("Serializer version included?")]
        SerializerVersionIncluded = 1 << 5,
        /// <summary>
        /// MAC included?
        /// </summary>
        [DisplayText("MAC included?")]
        MacIncluded = 1 << 6,
        /// <summary>
        /// Compressed?
        /// </summary>
        [DisplayText("Compressed?")]
        Compressed = 1 << 7,
        /// <summary>
        /// MAC algorithm included?
        /// </summary>
        [DisplayText("MAC algorithm included?")]
        MacAlgorithmIncluded = 1 << 8,
        /// <summary>
        /// KDF algorithm included?
        /// </summary>
        [DisplayText("KDF algorithm included?")]
        KdfAlgorithmIncluded = 1 << 9,
        /// <summary>
        /// Key exchange data included?
        /// </summary>
        [DisplayText("Key exchange data included?")]
        KeyExchangeDataIncluded = 1 << 10,
        /// <summary>
        /// Payload included
        /// </summary>
        [DisplayText("Payload included")]
        PayloadIncluded = 1 << 11,
        /// <summary>
        /// Time included?
        /// </summary>
        [DisplayText("Time included?")]
        TimeIncluded = 1 << 12,
        /// <summary>
        /// Is the MAC forced to cover all data?
        /// </summary>
        [DisplayText("Is the MAC forced to cover all data?")]
        ForceMacCoverWhole = 1 << 13,
        /// <summary>
        /// Require a counter MAC
        /// </summary>
        [DisplayText("Require a counter MAC")]
        RequireCounterMac = 1 << 14,
        /// <summary>
        /// Require an asymmetric counter algorithm
        /// </summary>
        [DisplayText("Require an asymmetric counter algorithm")]
        RequireAsymmetricCounterAlgorithm = 1 << 15,
        /// <summary>
        /// Require a counter KDF algorithm
        /// </summary>
        [DisplayText("Require a counter KDF algorithm")]
        RequireCounterKdfAlgorithm = 1 << 16,
        /// <summary>
        /// Include the private key revision?
        /// </summary>
        [DisplayText("Include the private key revision?")]
        PrivateKeyRevisionIncluded = 1 << 17,
        /// <summary>
        /// Require the private key revision to be included
        /// </summary>
        [DisplayText("Require the private key revision to be included")]
        RequirePrivateKeyRevision = 1 << 18,
        /// <summary>
        /// All flags
        /// </summary>
        [DisplayText("All flags")]
        FLAGS = HeaderVersionIncluded |
            SerializerVersionIncluded |
            MacIncluded |
            Compressed |
            MacAlgorithmIncluded |
            KdfAlgorithmIncluded |
            KeyExchangeDataIncluded |
            PayloadIncluded |
            TimeIncluded |
            PrivateKeyRevisionIncluded |
            ForceMacCoverWhole |
            RequireCounterMac |
            RequireAsymmetricCounterAlgorithm |
            RequireCounterKdfAlgorithm |
            RequirePrivateKeyRevision
    }
}
