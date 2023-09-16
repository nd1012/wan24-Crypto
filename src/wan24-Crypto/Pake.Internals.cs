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
            Options.Clear();
        }

        /// <summary>
        /// Create the authentication key
        /// </summary>
        /// <returns>Authentication key</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal byte[] CreateAuthKey()
            => Key?.Identifier?.Mac(Key.ExpandedKey, Options) ?? 
                throw CryptographicException.From(new InvalidOperationException("Unknown identity or initialized for server operation"));

        /// <summary>
        /// Create the secret
        /// </summary>
        /// <param name="key">Authentication key</param>
        /// <returns>Secret</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal byte[] CreateSecret(in byte[] key)
            => Key?.ExpandedKey.Array.Mac(key, Options) ?? throw CryptographicException.From(new InvalidOperationException("Initialized for server operation"));

        /// <summary>
        /// Create the signature key
        /// </summary>
        /// <param name="key">Authentication key</param>
        /// <param name="secret">Secret</param>
        /// <returns>Signature key</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal byte[] CreateSignatureKey(in byte[] key, in byte[] secret) => key.Stretch(key.Length, secret, Options).Stretched;

        /// <summary>
        /// Create the signature and the session key
        /// </summary>
        /// <param name="signatureKey">Signature key</param>
        /// <param name="key">Authentication key</param>
        /// <param name="random">Random bytes</param>
        /// <param name="payload">Payload</param>
        /// <param name="secret">Secret</param>
        /// <returns>Signature</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        [MemberNotNull(nameof(_SessionKey), nameof(SessionKey))]
        internal byte[] SignAndCreateSessionKey(in byte[] signatureKey, in byte[] key, in byte[] random, in byte[] payload, in byte[] secret)
        {
            byte[] identifier = Identifier,
                signature = null!;
            try
            {
                // Sign the PAKE sequence
                using (RentedArrayRefStruct<byte> signedData = new(len: random.Length + payload.Length + secret.Length + identifier.Length + key.Length, clean: false)
                {
                    Clear = true
                })
                {
                    int offset = random.Length;
                    random.AsSpan().CopyTo(signedData.Span);
                    if (payload.Length != 0)
                    {
                        payload.AsSpan().CopyTo(signedData.Span[offset..]);
                        offset += payload.Length;
                    }
                    secret.AsSpan().CopyTo(signedData.Span[offset..]);
                    offset += secret.Length;
                    identifier.AsSpan().CopyTo(signedData.Span[offset..]);
                    offset += identifier.Length;
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
            catch(Exception ex)
            {
                signature?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Clear the identity
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal void ClearIdentity()
        {
            if (Identity is null) return;
            Identity.Identifier.Clear();
            Identity.Secret.Clear();
            Identity.SignatureKey.Clear();
            Identity.TryDispose();
            Identity = null;
        }
    }
}
