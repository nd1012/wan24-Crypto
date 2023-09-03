using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using wan24.Core;

namespace wan24.Crypto
{
    // Internals
    public sealed partial class Pake
    {
        /// <summary>
        /// Session key
        /// </summary>
        private byte[]? _SessionKey = null;

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            ClearSessionKey();
            ClearIdentity();
            Key?.Dispose();
        }

        /// <summary>
        /// Create the authentication key
        /// </summary>
        /// <returns>Authentication key</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private byte[] CreateAuthKey()
            => Key?.Identifier?.Mac(Key.ExpandedKey, Options) ?? Identity?.Identifier.Mac(Identity.SignatureKey, Options) ?? throw new InvalidOperationException("Unknown identity");

        /// <summary>
        /// Create the secret
        /// </summary>
        /// <param name="key">Authentication key</param>
        /// <returns>Secret</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private byte[] CreateSecret(in byte[] key) => Key?.ExpandedKey.Mac(key, Options) ?? throw new InvalidOperationException("Missing symmetric key suite");

        /// <summary>
        /// Create the signature key
        /// </summary>
        /// <param name="key">Authentication key</param>
        /// <param name="identifier">Identifier</param>
        /// <returns>Signature key</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private byte[] CreateSignatureKey(in byte[] key, in byte[]? identifier = null)
            => key.Stretch(
                key.Length,
                identifier ?? Key?.Identifier ?? Identity?.Identifier ?? throw new ArgumentNullException(nameof(identifier)),
                Options
                )
                .Stretched;

        /// <summary>
        /// Create the signature and the session key
        /// </summary>
        /// <param name="signatureKey">Signature key</param>
        /// <param name="key">Authentication key</param>
        /// <param name="random">Random bytes</param>
        /// <param name="secret">Secret</param>
        /// <returns>Signature</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [MemberNotNull(nameof(_SessionKey), nameof(SessionKey))]
        private byte[] CreateSignatureAndSessionKey(in byte[] signatureKey, in byte[] key, in byte[] random, byte[]? secret = null)
        {
            byte[] identifier = Key?.Identifier ?? Identity?.Identifier ?? throw new InvalidOperationException("Unknown identity"),
                signature = null!;
            try
            {
                secret ??= Identity!.Secret;
                // Sign the PAKE sequence
                using (RentedArrayStruct<byte> signedData = new(len: secret.Length + identifier.Length + random.Length + key.Length, clean: false)
                {
                    Clear = true
                })
                {
                    int offset = secret.Length;
                    secret.AsSpan().CopyTo(signedData.Span);
                    identifier.AsSpan().CopyTo(signedData.Span[offset..]);
                    offset += identifier.Length;
                    random.AsSpan().CopyTo(signedData.Span[offset..]);
                    offset += random.Length;
                    key.AsSpan().CopyTo(signedData.Span[offset..]);
                    signature = signedData.Span.Mac(signatureKey, Options);
                }
                // Create the session key
                _SessionKey?.Clear();
                _SessionKey = random.Mac(signatureKey.Mac(secret, Options), Options);
#pragma warning disable CS8774 // Member "SessionKey" must not be NULL
                return signature;
#pragma warning restore CS8774 // Member "SessionKey" must not be NULL
            }
            catch
            {
                signature?.Clear();
                throw;
            }
        }

        /// <summary>
        /// Clear the identity
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ClearIdentity()
        {
            if (Identity is null) return;
            Identity.Identifier.Clear();
            Identity.Secret.Clear();
            Identity.SignatureKey.Clear();
            Identity = null;
        }
    }
}
