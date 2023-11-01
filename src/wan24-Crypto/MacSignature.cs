using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto
{
    /// <summary>
    /// MAC signature helper
    /// </summary>
    public sealed record class MacSignature : DisposableRecordBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Key (won't be cleared, if it's not the shared key)</param>
        /// <param name="isSharedKey">Is the <c>key</c> the shared key?</param>
        /// <param name="options">Options (won't be cleared)</param>
        public MacSignature(in byte[] key, in bool isSharedKey, in CryptoOptions? options = null) : base(asyncDisposing: false)
        {
            Options = isSharedKey
                ? MacHelper.GetDefaultOptions(MacHelper.GetAlgorithm(MacHelper.GetAlgorithmName(key.Length)).DefaultOptions)
                : MacHelper.GetDefaultOptions(options);
            SharedKey = isSharedKey ? new(key) : new(key.Mac(key, Options));
        }

        /// <summary>
        /// Options
        /// </summary>
        public CryptoOptions Options { get; }

        /// <summary>
        /// Shared key (should be stored encrypted at the validator!)
        /// </summary>
        [SensitiveData, NoValidation]
        public SecureByteArray SharedKey { get; }

        /// <summary>
        /// Create a signature
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <returns>Signature</returns>
        public byte[] Sign(in ReadOnlySpan<byte> data)
        {
            EnsureUndisposed();
            byte[] res = new byte[SharedKey.Length << 1];
            Span<byte> signature = res.AsSpan(SharedKey.Length),
                verification = res.AsSpan(0, SharedKey.Length);
            RND.FillBytes(verification);
            verification.Xor(SharedKey.Span);
            using SecureByteArrayRefStruct signatureKey = new(verification.ToArray());
            data.Mac(signatureKey, signature, Options);
            return res;
        }

        /// <summary>
        /// Create a signature
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <returns>Signature</returns>
        public async Task<byte[]> SignAsync(ReadOnlyMemory<byte> data)
        {
            EnsureUndisposed();
            byte[] res = new byte[SharedKey.Length << 1];
            Memory<byte> signature = res.AsMemory(SharedKey.Length),
                verification = res.AsMemory(0, SharedKey.Length);
            await RND.FillBytesAsync(verification).DynamicContext();
            verification.Span.Xor(SharedKey.Span);
            using SecureByteArrayStructSimple signatureKey = new(verification.ToArray());
            data.Span.Mac(signatureKey, signature.Span, Options);
            return res;
        }

        /// <summary>
        /// Validate a signature (and authenticate the signer)
        /// </summary>
        /// <param name="signedData">Signed data</param>
        /// <param name="dataSignature">Signature</param>
        /// <returns>If the signature is valid for the signed data, and the signer is authenticated</returns>
        public bool Validate(in ReadOnlySpan<byte> signedData, in ReadOnlySpan<byte> dataSignature)
        {
            EnsureUndisposed();
            if (dataSignature.Length != SharedKey.Length << 1) return false;
            ReadOnlySpan<byte> signature = dataSignature[SharedKey.Length..],
                verification = dataSignature[..SharedKey.Length];
            using SecureByteArrayRefStruct rnd = new(verification.ToArray().Xor(SharedKey.Span));
            using SecureByteArrayRefStruct signatureKey = new(verification.ToArray());
            using SecureByteArrayRefStruct signatureB = new(signedData.Mac(signatureKey.Array, Options));
            return signature.SlowCompare(signatureB.Span) && signatureKey.Span.Xor(rnd.Span).SlowCompare(SharedKey.Span);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => SharedKey.Dispose();

        /// <summary>
        /// Authenticate signed data (won't authenticate the signer!)
        /// </summary>
        /// <param name="signedData">Signed data</param>
        /// <param name="dataSignature">Signature</param>
        /// <returns>If the signature is valid for the signed data (won't authenticate the signer!)</returns>
        public static bool AuthenticateSignedData(in ReadOnlySpan<byte> signedData, in ReadOnlySpan<byte> dataSignature)
        {
            if (dataSignature.Length < 2) return false;
            using SecureByteArrayRefStruct signatureKey = new(dataSignature[..(dataSignature.Length >> 1)].ToArray());
            using RentedArrayRefStruct<byte> mac = new(dataSignature.Length >> 1, clean: false)
            {
                Clear = true
            };
            return signedData.Mac(
                signatureKey.Array, 
                mac.Span,
                MacHelper.GetDefaultOptions(MacHelper.GetAlgorithm(MacHelper.GetAlgorithmName(dataSignature.Length >> 1)).DefaultOptions)
                )
                .SlowCompare(dataSignature[(dataSignature.Length >> 1)..]);
        }
    }
}
