namespace wan24.Crypto.Authentication
{
    // Internals
    public sealed partial class PakeServerAuth
    {
        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Options.PakeOptions?.Clear();
            Options.CryptoOptions?.Clear();
        }

        /// <summary>
        /// Set the matching and allowed MAC algorithm name
        /// </summary>
        /// <param name="len">Digest length in byte</param>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        private CryptoOptions SetMacAlgorithm(int len, CryptoOptions options)
            => options.MacAlgorithm is not null && MacHelper.GetAlgorithm(options.MacAlgorithm).MacLength == len
                ? options
                : options.WithMac(MacHelper.GetAlgorithmName(len, Options.AllowedMacAlgorithms), included: false);
    }
}
