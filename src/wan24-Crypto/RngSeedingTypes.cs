using wan24.Core;

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
        [DisplayText("None (no automatic RNG seeding from decryption or external random sources)")]
        None,
        /// <summary>
        /// Seed received IV bytes during decryption
        /// </summary>
        [DisplayText("Seed received IV bytes during decryption")]
        Iv,
        /// <summary>
        /// Seed received cipher data during decryption
        /// </summary>
        [DisplayText("Seed received cipher data during decryption")]
        CipherData,
        /// <summary>
        /// Seed received random data
        /// </summary>
        [DisplayText("Seed received random data")]
        Random
    }
}
