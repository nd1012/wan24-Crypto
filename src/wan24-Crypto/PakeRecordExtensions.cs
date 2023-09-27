using wan24.Core;

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

        /// <summary>
        /// Dispose the PAKE record
        /// </summary>
        /// <param name="record">Record</param>
        public static void Dispose(this IPakeRecord record)
        {
            if (record is IDisposable disposable)
            {
                disposable.Dispose();
            }
            else if (record is IAsyncDisposable asyncDisposable)
            {
                asyncDisposable.DisposeAsync().AsTask().Wait();
            }
            else if(record is PakeRecord pakeRecord)
            {
                pakeRecord.Clear();
            }
            else
            {
                record.Identifier.Clear();
                record.Secret.Clear();
                record.SignatureKey.Clear();
            }
        }

        /// <summary>
        /// Dispose the PAKE record
        /// </summary>
        /// <param name="record">Record</param>
        public static async Task DisposeAsync(this IPakeRecord record)
        {
            if (record is IAsyncDisposable asyncDisposable)
            {
                await asyncDisposable.DisposeAsync().DynamicContext();
            }
            else if (record is IDisposable disposable)
            {
                disposable.Dispose();
            }
            else if (record is PakeRecord pakeRecord)
            {
                pakeRecord.Clear();
            }
            else
            {
                record.Identifier.Clear();
                record.Secret.Clear();
                record.SignatureKey.Clear();
            }
        }
    }
}
