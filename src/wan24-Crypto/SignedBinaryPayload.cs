namespace wan24.Crypto
{
    /// <summary>
    /// Signed binary payload
    /// </summary>
    public sealed class SignedBinaryPayload : SignedBinaryPayload<BinaryPayloadContainer>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public SignedBinaryPayload() : base() { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="payload">Payload</param>
        /// <param name="privateKey">Private key</param>
        /// <param name="options">Options</param>
        public SignedBinaryPayload(BinaryPayloadContainer payload, ISignaturePrivateKey privateKey, CryptoOptions? options = null) : base(payload, privateKey, options) { }
    }

    /// <summary>
    /// Signed binary payload
    /// </summary>
    /// <typeparam name="T">Binary payload container type</typeparam>
    public abstract class SignedBinaryPayload<T> : SignedPayload<T> where T : BinaryPayloadContainer, new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        protected SignedBinaryPayload() : base() { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="payload">Payload</param>
        /// <param name="privateKey">Private key</param>
        /// <param name="options">Options</param>
        protected SignedBinaryPayload(T payload, ISignaturePrivateKey privateKey, CryptoOptions? options = null) : base(payload, privateKey, options) { }
    }
}
