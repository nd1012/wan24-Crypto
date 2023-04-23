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
        KeyExchange = 1,
        /// <summary>
        /// Signature
        /// </summary>
        Signature = 2
    }
}
