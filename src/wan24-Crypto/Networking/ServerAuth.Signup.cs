using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Networking
{
    // Signup
    public sealed partial class ServerAuth
    {
        /// <summary>
        /// Process a signup
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="preSharedSecret">Pre-shared secret</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Client authentication context</returns>
        private async Task<ClientAuthContext> ProcessSignupAsync(Stream stream, byte[]? preSharedSecret, CancellationToken cancellationToken)
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
                    // PAKE signup
                    using PakeSignup signup = await decipher.CryptoStream.ReadSerializedAsync<PakeSignup>(cancellationToken: cancellationToken).DynamicContext();
                    await hash.FinalizeHashAsync(transformFinal: true).DynamicContext();
                    context.Signup = signup;
                    await Options.IdentityFactory!(context, cancellationToken).DynamicContext();
                    using (Pake pake = new(context.PakeOptions.Clone(), context.CryptoOptions.Clone()))
                    {
                        pake.OnSignup += (s, e) => OnPakeSignup?.Invoke(this, new(context, pake, e));
                        payload = pake.HandleSignup(signup);
                        context.Identity ??= new PakeRecord(pake.Identity);
                        context.CryptoOptions.Password = context.CryptoOptions.Password!.ExtendKey(pake.SessionKey, preSharedSecret);
                    }
                    context.Payload = payload;
                    context.ClientTimeOffset = DateTime.UtcNow - context.Payload.Created;
                    if(context.PublicClientKeys is null)
                    {
                        if (context.Payload.PublicKeys is null) throw new InvalidDataException("No public client keys loaded and in signup payload");
                        context.PublicClientKeys = context.Payload.PublicKeys;
                    }
                    await decipher.DisposeAsync().DynamicContext();
                    decipher = await Encryption!.GetDecryptionStreamAsync(stream, Stream.Null, context.CryptoOptions, cancellationToken).DynamicContext();
                    // Validate the authentication sequence signature
                    await ValidateAuthSequenceAsync(context, hash.Hash, decipher, ClientAuth.SIGNUP_SIGNATURE_PURPOSE, cancellationToken).DynamicContext();
                    await decipher.DisposeAsync().DynamicContext();
                    decipher = null;
                    // Validate the payload
                    if (context.Payload.PublicKeys is null && context.Payload.KeySigningRequest is not null)
                        throw new InvalidDataException("Invalid payload configuration");
                    if (context.Payload.IsTemporaryClient && !Options.AllowTemporaryClient)
                        throw new UnauthorizedAccessException("Temporary client signup denied");
                    if (!context.Payload.Created.IsInRange(Options.MaxTimeDifference, DateTime.UtcNow))
                        throw new InvalidDataException("Max. peer time difference exceeded");
                    if(context.Payload.PublicKeys is PublicKeySuite clientPublicKeys)
                    {
                        if (clientPublicKeys.KeyExchangeKey is null) throw new InvalidDataException("Missing client public key exchange key");
                        if (Options.PrivateKeys.CounterKeyExchangeKey is not null && clientPublicKeys.KeyExchangeKey is null)
                            throw new InvalidDataException("Missing client public counter key exchange key");
                        if (clientPublicKeys.SignatureKey is null) throw new InvalidDataException("Missing client public signature key");
                        if(!clientPublicKeys.SignatureKey.ID.SequenceEqual(context.Payload.PublicKeyId!))
                            throw new InvalidDataException("Public client key ID mismatch");
                        if (clientPublicKeys.KeyExchangeKey.Algorithm.Name != Options.PrivateKeys.KeyExchangeKey!.Algorithm.Name)
                            throw new InvalidDataException("Client public key exchange key algorithm mismatch");
                        if (clientPublicKeys.KeyExchangeKey.Bits != Options.PrivateKeys.KeyExchangeKey!.Bits)
                            throw new InvalidDataException("Client public key exchange key size mismatch");
                        if(Options.PrivateKeys.CounterKeyExchangeKey is not null)
                        {
                            if (clientPublicKeys.CounterKeyExchangeKey!.Algorithm.Name != Options.PrivateKeys.CounterKeyExchangeKey!.Algorithm.Name)
                                throw new InvalidDataException("Client public counter key exchange key algorithm mismatch");
                            if (clientPublicKeys.CounterKeyExchangeKey.Bits != Options.PrivateKeys.CounterKeyExchangeKey!.Bits)
                                throw new InvalidDataException("Client public counter key exchange key size mismatch");
                        }
                    }
                    if (context.Payload.KeySigningRequest is AsymmetricPublicKeySigningRequest ksr)
                    {
                        if (ksr.Signature is not null) ksr.ValidateRequestSignature();
                        if (!ksr.PublicKey.ID.SequenceEqual(context.Payload.PublicKeyId!))
                            throw new InvalidDataException("Public client key signature request key ID mismatch");
                    }
                    if (Options.SignupValidator is not null && !await Options.SignupValidator(context, cancellationToken).DynamicContext())
                        throw new InvalidDataException("Client signup rejected");
                    // Exchange the PFS key and sign the authentication sequence
                    await stream.WriteAsync((byte)AuthSequences.Signup, cancellationToken).DynamicContext();
                    cipher = await Encryption!.GetEncryptionStreamAsync(Stream.Null, stream, macStream: null, context.CryptoOptions, cancellationToken).DynamicContext();
                    cipher = await ExtendEncryptionAsync(context, cipher, cancellationToken).DynamicContext();
                    await SignAuthSequenceAsync(context, cipher!, hash.Hash, ClientAuth.SIGNUP_SIGNATURE_PURPOSE, cancellationToken).DynamicContext();
                    // Send the signed public key
                    if (context.Payload.KeySigningRequest is not null)
                    {
                        AsymmetricSignedPublicKey signedKey = context.Payload.KeySigningRequest.GetAsUnsignedKey();
                        try
                        {
                            signedKey.Sign(
                                Options.PrivateKeys.SignatureKey!,
                                Options.PrivateKeys.SignedPublicKey,
                                Options.PrivateKeys.CounterSignatureKey,
                                Options.PrivateKeys.SignedPublicCounterKey,
                                Options.PublicClientKeySignaturePurpose,
                                context.HashOptions
                                );
                            context.PublicClientKeys!.SignedPublicKey = signedKey;
                            await cipher!.CryptoStream.WriteSerializedAsync(signedKey, cancellationToken).DynamicContext();
                        }
                        catch
                        {
                            signedKey.Dispose();
                            throw;
                        }
                    }
                    if (Options.SignupHandler is not null) await Options.SignupHandler(context, cancellationToken).DynamicContext();
                    await context.Stream.FlushAsync(cancellationToken).DynamicContext();
                    return new(Options, context, !context.FoundExistingClient && context.Payload.IsNewClient, !context.FoundExistingClient && context.Payload.IsTemporaryClient);
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
                    context.Signup?.Dispose();
                    context.ClientPfsKeys?.Dispose();
                    context.CryptoOptions.Clear();
                    context.PakeOptions.Clear();
                    if (context.Identity is not null) await context.Identity.DisposeAsync().DynamicContext();
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
