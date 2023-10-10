namespace wan24.Crypto
{
    /// <summary>
    /// RNG seeding types (CAUTION: be aware of patent US10402172B1!)
    /// </summary>
    [Flags]
    public enum RngSeedingTypes
    {
        /// <summary>
        /// None (no automatic RNG seeding from decryption or external random sources)
        /// </summary>
        None,
        /// <summary>
        /// Seed received IV bytes during decryption
        /// </summary>
        Iv,
        /// <summary>
        /// Seed received cipher data during decryption
        /// </summary>
        CipherData,
        /// <summary>
        /// Seed received random data
        /// </summary>
        Random
    }
}
