using Microsoft.Extensions.Primitives;
using System.ComponentModel;
using wan24.Core;
using wan24.Crypto.Authentication;

namespace wan24.Crypto
{
    /// <summary>
    /// Fast PAKE authentication server (will skip KDF after initialization)
    /// </summary>
    public sealed partial class FastPakeAuthServer : DisposableBase, IStatusProvider, IChangeToken, INotifyPropertyChanged
    {
        /// <summary>
        /// Handle an authentication
        /// </summary>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="decryptPayload">Decrypt the payload, if any? (for this the identity must be available already when calling this method!)</param>
        /// <param name="payloadProcessor">Payload processor</param>
        /// <returns>Payload and session key (should be cleared!)</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        public (byte[] Payload, byte[] SessionKey) HandleAuth(
            in IPakeRequest auth, 
            in bool decryptPayload = false, 
            in Pake.PayloadProcessor_Delegate? payloadProcessor = null
            )
        {
            byte[]? payload = null,
                randomMac = null,
                sessionKey = null,
                signatureKey = null;
            SemaphoreSyncContext? ssc = null;
            try
            {
                EnsureUndisposed();
                if (UseSync) ssc = Sync;
                _AuthCount++;
                SetChanged(nameof(AuthCount));
                // Decrypt the payload
                signatureKey = SignatureKey;
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                    randomMac = auth.Random.Mac(signatureKey, Pake.Options);
                    payload = Pake.DecryptPayload(auth.Payload, randomMac);
                }
                // Run pre-actions
                Pake.PakeServerEventArgs e = new(auth, payload);
                Pake.RaiseOnAuth(e);
                if (e.NewIdentity is not null)
                {
                    Pake.ClearIdentity();
                    Pake.Identity = e.NewIdentity;
                }
                // Validate pre-conditions
                if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                if (!Pake.Identity.Identifier.SlowCompare(auth.Identifier)) throw CryptographicException.From(new InvalidDataException("Identity mismatch"));
                byte[] key = null!,
                    secret = null!,
                    signature = null!;
                int len = auth.Identifier.Length;
                try
                {
                    // Validate the auth values lengths
                    if (auth.Key.Length != len || auth.Signature.Length != len || auth.Random.Length != len)
                        throw CryptographicException.From(new InvalidDataException("Value lengths invalid"));
                    // Apply RNG seeding
                    if (((Pake.CryptoOptions.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                        RND.AddSeed(auth.Random);
                    // Extract key and secret
                    signatureKey = SignatureKey;
                    randomMac ??= auth.Random.Mac(signatureKey);
                    key = Key;
                    if (!auth.Key.Xor(randomMac).SlowCompare(key)) throw CryptographicException.From(new InvalidDataException("Authentication key invalid"));
                    // Validate the signature and create the session key (MAC)
                    secret = Secret;
                    (signature, sessionKey) = Pake.SignAndCreateSessionKey2(signatureKey, key, auth.Random, auth.Payload, secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    return (payloadProcessor is null ? payload ?? auth.Payload.CloneArray() : payloadProcessor(Pake, auth.Random, payload ?? auth.Payload), sessionKey);
                }
                finally
                {
                    signature?.Clear();
                    key?.Clear();
                    secret?.Clear();
                    if (payloadProcessor is not null) payload?.Clear();
                }
            }
            catch (Exception ex)
            {
                _AuthErrorCount++;
                SetChanged(nameof(AuthErrorCount));
                Pake.RaiseOnAuthError(new(auth, payload, ex));
                payload?.Clear();
                sessionKey?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                auth.Dispose();
                signatureKey?.Clear();
                randomMac?.Clear();
                ssc?.Dispose();
            }
        }

        /// <summary>
        /// Handle an authentication
        /// </summary>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="decryptPayload">Decrypt the payload, if any? (for this the identity must be available already when calling this method!)</param>
        /// <param name="payloadProcessor">Payload processor</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Payload and session key (should be cleared!)</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        public async Task<(byte[] Payload, byte[] SessionKey)> HandleAuthAsync(
            IPakeRequest auth, 
            bool decryptPayload = false,
            Pake.PayloadProcessor_Delegate? payloadProcessor = null,
            CancellationToken cancellationToken = default
            )
        {
            byte[]? payload = null,
                randomMac = null,
                sessionKey = null,
                signatureKey = null;
            SemaphoreSyncContext? ssc = null;
            try
            {
                EnsureUndisposed();
                if (UseSync) ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
                _AuthCount++;
                SetChanged(nameof(AuthCount));
                // Decrypt the payload
                signatureKey = SignatureKey;
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Pake.Identity is null) throw await CryptographicException.FromAsync(new InvalidOperationException("Unknown identity")).DynamicContext();
                    randomMac = auth.Random.Mac(signatureKey, Pake.Options);
                    payload = Pake.DecryptPayload(auth.Payload, randomMac);
                }
                // Run pre-actions
                Pake.PakeServerEventArgs e = new(auth, payload);
                Pake.RaiseOnAuth(e);
                if (e.NewIdentity is not null)
                {
                    Pake.ClearIdentity();
                    Pake.Identity = e.NewIdentity;
                }
                // Validate pre-conditions
                if (Pake.Identity is null) throw await CryptographicException.FromAsync(new InvalidOperationException("Unknown identity")).DynamicContext();
                if (!Pake.Identity.Identifier.SlowCompare(auth.Identifier))
                    throw await CryptographicException.FromAsync(new InvalidDataException("Identity mismatch")).DynamicContext();
                byte[] key = null!,
                    secret = null!,
                    signature = null!;
                int len = auth.Identifier.Length;
                try
                {
                    // Validate the auth values lengths
                    if (auth.Key.Length != len || auth.Signature.Length != len || auth.Random.Length != len)
                        throw await CryptographicException.FromAsync(new InvalidDataException("Value lengths invalid")).DynamicContext();
                    // Apply RNG seeding
                    if (((Pake.CryptoOptions.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                        await RND.AddSeedAsync(auth.Random, cancellationToken).DynamicContext();
                    // Extract key and secret
                    signatureKey = SignatureKey;
                    randomMac ??= auth.Random.Mac(signatureKey);
                    key = Key;
                    if (!auth.Key.Xor(randomMac).SlowCompare(key))
                        throw await CryptographicException.FromAsync(new InvalidDataException("Authentication key invalid")).DynamicContext();
                    // Validate the signature and create the session key (MAC)
                    secret = Secret;
                    (signature, sessionKey) = Pake.SignAndCreateSessionKey2(signatureKey, key, auth.Random, auth.Payload, secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw await CryptographicException.FromAsync(new InvalidDataException("Signature validation failed")).DynamicContext();
                    return (payloadProcessor is null ? payload ?? auth.Payload.CloneArray() : payloadProcessor(Pake, auth.Random, payload ?? auth.Payload), sessionKey);
                }
                finally
                {
                    signature?.Clear();
                    key?.Clear();
                    secret?.Clear();
                    if (payloadProcessor is not null) payload?.Clear();
                }
            }
            catch (Exception ex)
            {
                _AuthErrorCount++;
                SetChanged(nameof(AuthErrorCount));
                Pake.RaiseOnAuthError(new(auth, payload, ex));
                payload?.Clear();
                sessionKey?.Clear();
                if (ex is CryptographicException) throw;
                throw await CryptographicException.FromAsync(ex).DynamicContext();
            }
            finally
            {
                auth.Dispose();
                signatureKey?.Clear();
                randomMac?.Clear();
                ssc?.Dispose();
            }
        }

        /// <summary>
        /// Create a PAKE authentication record from this instance
        /// </summary>
        /// <returns>Record (don't forget to clear!)</returns>
        public PakeAuthRecord CreateAuthRecord()
        {
            EnsureUndisposed();
            return new(Pake.Identity!.Identifier.CloneArray(), Secret, Key, SignatureKey);
        }
    }
}
