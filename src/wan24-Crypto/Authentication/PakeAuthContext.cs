using wan24.Core;
using wan24.ObjectValidation;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication context
    /// </summary>
    public sealed record class PakeAuthContext : DisposableRecordBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="sessionKey">Session key (will be cleared!)</param>
        /// <param name="payload">Payload (for signup only; will be cleared!)</param>
        /// <param name="record">PAKE authentication record (for signup only; will be cleared/disposed!)</param>
        internal PakeAuthContext(
            in PakeClientAuthOptions options,
            in byte[] sessionKey,
            in byte[]? payload = null,
            in IPakeAuthRecord? record = null
            )
            : base()
        {
            SessionKey = new(sessionKey, options.EncryptTimeout, options.RecryptTimeout, options.SessionKeyCryptoOptions, options.SessionKeyKekLength);
            Payload = payload;
            Record = record;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="sessionKey">Session key (will be cleared!)</param>
        internal PakeAuthContext(in PakeServerAuthContext context, in byte[] sessionKey) : base()
        {
            try
            {
                Identity = context.ClientIdentity;
                SessionKey = new(
                    sessionKey, 
                    context.ServerAuthentication.Options.EncryptTimeout,
                    context.ServerAuthentication.Options.RecryptTimeout,
                    context.ServerAuthentication.Options.CryptoOptions,
                    context.ServerAuthentication.Options.SessionKeyKekLength
                    );
                Payload = context.ClientPayload?.Payload?.CloneArray();
                Record = context.ServerIdentity;
                ClientTimeOffset = context.ClientTimeOffset;
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        /// <summary>
        /// Session key (will be disposed!)
        /// </summary>
        [NoValidation]
        public SecureValue SessionKey { get; }

        /// <summary>
        /// Payload (will be cleared!)
        /// </summary>
        byte[]? Payload { get; }

        /// <summary>
        /// Peer identity (will be cleared/disposed!)
        /// </summary>
        public IPakeRecord? Identity { get; }

        /// <summary>
        /// PAKE autthentication record (for signup only; will be cleared!)
        /// </summary>
        public IPakeAuthRecord? Record { get; }

        /// <summary>
        /// Client time offset (server side only)
        /// </summary>
        public TimeSpan? ClientTimeOffset { get; }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            SessionKey.Dispose();
            Identity?.Dispose();
            Payload?.Clear();
            Record?.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await SessionKey.DisposeAsync().DynamicContext();
            if (Identity is not null) await Identity.DisposeAsync().DynamicContext();
            Payload?.Clear();
            Record?.Dispose();
        }
    }
}
