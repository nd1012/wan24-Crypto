using System.Runtime.CompilerServices;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Fast PAKE authentication client (NOT thread-safe!)
    /// </summary>
    public sealed class FastPakeAuthClient : DisposableBase
    {
        /// <summary>
        /// Key
        /// </summary>
        private readonly SecureByteArray Key;
        /// <summary>
        /// Secret
        /// </summary>
        private readonly SecureByteArray Secret;
        /// <summary>
        /// Signature key
        /// </summary>
        private readonly SecureByteArray SignatureKey;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        public FastPakeAuthClient(SymmetricKeySuite key) : base(asyncDisposing: false)
        {
            Pake = new(key);
            Key = new(Pake.CreateAuthKey());
            Secret = new(Pake.CreateSecret(Key));
            SignatureKey = new(Pake.CreateSignatureKey(Key, Secret));
        }

        /// <summary>
        /// PAKE instance
        /// </summary>
        public Pake Pake { get; }

        /// <summary>
        /// Identifier
        /// </summary>
        public byte[] Identifier
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => Pake.Identifier;
        }

        /// <summary>
        /// Has a session key?
        /// </summary>
        public bool HasSession
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => Pake.HasSession;
        }

        /// <summary>
        /// Session key (available after authentication; will be cleared!)
        /// </summary>
        public byte[] SessionKey
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => Pake.SessionKey;
        }

        /// <summary>
        /// Create an authentication
        /// </summary>
        /// <param name="payload">Payload (max. <see cref="ushort.MaxValue"/> length; will be cleared!)</param>
        /// <param name="encryptPayload">Encrypt the payload?</param>
        /// <returns>Authentication (send this to the server and don't forget to dispose!)</returns>
        public PakeAuth CreateAuth(byte[]? payload = null, bool encryptPayload = false)
        {
            EnsureUndisposed();
            if (Pake.Key?.Identifier is null) throw CryptographicException.From(new InvalidOperationException("Initialized for server operation or missing identifier"));
            byte[] random = RND.GetBytes(Pake.Key.ExpandedKey.Length),
                randomMac = null!,
                signature = null!;
            try
            {
                if (encryptPayload && payload is not null)
                {
                    byte[] dek = random.Mac(SignatureKey, Pake.Options);
                    try
                    {
                        payload = payload.Encrypt(dek, Pake.Options);
                    }
                    finally
                    {
                        dek.Clear();
                    }
                }
                randomMac = random.Mac(SignatureKey);
                signature = Pake.SignAndCreateSessionKey(SignatureKey, Key, random, payload ?? Array.Empty<byte>(), Secret);// MAC
                return new PakeAuth(Identifier.CloneArray(), Key.Array.CloneArray().Xor(randomMac), signature, random, payload);
            }
            catch (Exception ex)
            {
                random.Clear();
                signature?.Clear();
                payload?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                randomMac?.Clear();
            }
        }

        /// <summary>
        /// Clear the session key
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void ClearSessionKey() => Pake?.ClearSessionKey();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Pake.Dispose();
            Secret.Dispose();
            Key.Dispose();
            SignatureKey.Dispose();
        }
    }
}
