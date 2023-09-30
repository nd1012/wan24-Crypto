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
    }
}
