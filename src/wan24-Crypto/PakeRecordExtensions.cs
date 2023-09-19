namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="IPakeRecord"/> extensions
    /// </summary>
    public static class PakeRecordExtensions
    {
        /// <summary>
        /// Derive a session key
        /// </summary>
        /// <param name="record">Record (will be cleared/disposed!)</param>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="initializer">PAKE instance initializer</param>
        /// <param name="options">Options</param>
        /// <param name="cryptoOptions">Options for encryption</param>
        /// <param name="decryptPayload">Decrypt the payload?</param>
        /// <returns>Session key and payload</returns>
        public static (byte[] SessionKey, byte[] Payload) DeriveSessionKey(
            this IPakeRecord record,
            in PakeAuth auth,
            in Action<Pake>? initializer = null,
            in CryptoOptions? options = null,
            in CryptoOptions? cryptoOptions = null,
            in bool decryptPayload = false
            )
            => Pake.DeriveSessionKey(record, auth, initializer, options, cryptoOptions, decryptPayload);
    }
}
