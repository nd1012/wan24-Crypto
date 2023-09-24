using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Networking
{
    // Authentication
    public sealed partial class ServerAuth
    {
        /// <summary>
        /// Process an authentication
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Client authentication context</returns>
        private async Task<ClientAuthContext> ProcessAuthenticationAsync(Stream stream, CancellationToken cancellationToken)
        {
            CryptoOptions hashOptions = Options.HashOptions!.Clone();
            try
            {
                using HashStreams hash = HashHelper.GetAlgorithm(hashOptions.HashAlgorithm!).GetHashStream(stream, writable: false, hashOptions);
                await ValidateProtocolVersionAsync(hash.Stream, cancellationToken).DynamicContext();
                DecryptionStreams? decipher = null;
                EncryptionStreams? cipher = null;
                byte[]? payload = null;
                ServerAuthContext context = new(this, stream, hashOptions, Options.PakeOptions!.Clone(), Options.CryptoOptions!.Clone());
                try
                {
                    decipher = await StartDecryptionAsync(context, hash, cancellationToken).DynamicContext();
                    // PAKE authentication
                    using PakeAuth auth = await decipher.CryptoStream.ReadSerializedAsync<PakeAuth>(cancellationToken: cancellationToken).DynamicContext();
                    context.Authentication = auth;
                    await Options.IdentityFactory!(context, cancellationToken).DynamicContext();
                    if (context.Identity is null) throw new UnauthorizedAccessException("No identity found");
                    if (context.PublicClientKeys is null) throw new UnauthorizedAccessException("Missing client public keys");
                    using (Pake pake = new(context.Identity, context.PakeOptions.Clone(), context.CryptoOptions.Clone()))
                    {
                        pake.OnAuth += (s, e) => OnPakeAuth?.Invoke(this, new(context, pake, e));
                        pake.OnAuthError += (s, e) => OnPakeAuthError?.Invoke(this, new(context, pake, e));
                        payload = pake.HandleAuth(auth, Options.DecryptPayload, Options.SkipPakeSignatureKeyValidation);
                        context.CryptoOptions.Password = context.CryptoOptions.Password!.ExtendKey(pake.SessionKey);
                    }
                    context.Payload = payload;
                    context.ClientTimeOffset = DateTime.UtcNow - context.Payload.Created;
                    if (!context.Payload.Created.IsInRange(Options.MaxTimeDifference, DateTime.UtcNow))
                        throw new InvalidDataException("Max. peer time difference exceeded");
                    hash.Stream.Dispose();
                    hash.Transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                    await decipher.DisposeAsync().DynamicContext();
                    decipher = await Encryption!.GetDecryptionStreamAsync(stream, Stream.Null, context.CryptoOptions, cancellationToken).DynamicContext();
                    // Validate the authentication sequence signature
                    await ValidateAuthSequenceAsync(context, hash.Hash, decipher, ClientAuth.AUTH_SIGNATURE_PURPOSE, cancellationToken).DynamicContext();
                    // Sign the authentication sequence
                    if (!Options.SendAuthenticationResponse) return new(context, isNewClient: false);
                    await decipher.DisposeAsync().DynamicContext();
                    decipher = null;
                    cipher = await Encryption!.GetEncryptionStreamAsync(Stream.Null, stream, macStream: null, context.CryptoOptions, cancellationToken).DynamicContext();
                    await SignAuthSequenceAsync(context, cipher, hash.Hash, ClientAuth.AUTH_SIGNATURE_PURPOSE, cancellationToken).DynamicContext();
                    // Exchange a PFS session key
                    cipher = await ExtendEncryptionAsync(context, cipher, returnCipher: false, cancellationToken).DynamicContext();
                    if (Options.AuthenticationHandler is not null) await Options.AuthenticationHandler(context, cancellationToken).DynamicContext();
                    return new(context);
                }
                catch
                {
                    context.PublicClientKeys?.Dispose();
                    context.Payload?.Payload?.Clear();
                    throw;
                }
                finally
                {
                    if (decipher is not null) await decipher.DisposeAsync().DynamicContext();
                    if (cipher is not null) await cipher.DisposeAsync().DynamicContext();
                    context.ClientPfsKeys?.Dispose();
                    context.CryptoOptions.Clear();
                    context.PakeOptions.Clear();
                    if (context.Identity is not null)
                    {
                        context.Identity.Identifier.Clear();
                        context.Identity.Secret.Clear();
                        context.Identity.SignatureKey.Clear();
                        await context.Identity.TryDisposeAsync().DynamicContext();
                    }
                    context.Authentication?.Dispose();
                    payload?.Clear();
                }
            }
            finally
            {
                hashOptions.Clear();
            }
        }
    }
}
