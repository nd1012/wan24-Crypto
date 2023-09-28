namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE server authentication options
    /// </summary>
    public sealed class PakeServerAuthOptions
    {
        /// <summary>
        /// Cnstructor
        /// </summary>
        public PakeServerAuthOptions() { }

        /// <summary>
        /// Decrypt the payload?
        /// </summary>
        public bool DecryptPayload { get; set; }

        /// <summary>
        /// PAKE options (require KDF and MAC algorithms)
        /// </summary>
        public CryptoOptions? PakeOptions { get; set; }

        /// <summary>
        /// Crypto options (require encryption algorithms; shouldn't use KDF)
        /// </summary>
        public CryptoOptions? CryptoOptions { get; set; }
    }
}
