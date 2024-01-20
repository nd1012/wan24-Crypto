using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Asymmetric algorithm usages
    /// </summary>
    [Flags]
    public enum AsymmetricAlgorithmUsages
    {
        /// <summary>
        /// Key exchange
        /// </summary>
        [DisplayText("Key exchange")]
        KeyExchange = 1,
        /// <summary>
        /// Signature
        /// </summary>
        [DisplayText("Signature")]
        Signature = 2
    }
}
