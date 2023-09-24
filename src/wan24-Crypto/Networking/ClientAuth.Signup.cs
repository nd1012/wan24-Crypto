using System.Buffers;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Networking
{
    // Signup
    public static partial class ClientAuth
    {
        /// <summary>
        /// Signup
        /// </summary>
        /// <param name="stream">Stream (requires blocking)</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PFS session key (should be cleared!)</returns>
        public static async Task<byte[]> SignupAsync(
            Stream stream,
            ClientAuthOptions options,
            CancellationToken cancellationToken = default
            )
        {
            bool disposeServerKey = options.PublicServerKeys is null;
            SymmetricKeySuite? symmetricKey = null;
            byte[]? authPayload = null,
                sessionKey = null;
            CryptoOptions? hashOptions = null,
                pakeOptions = null,
                cryptoOptions = null,
                pakeCryptoOptions = null;
            AsymmetricSignedPublicKey? signedPublicKey = null;
            try
            {
                // Ensure valid parameters
                if (options.PrivateKeys.KeyExchangeKey is null) throw new ArgumentException("Missing private key exchange key", nameof(options));
                if (options.PrivateKeys.SignatureKey is null) throw new ArgumentException("Missing private signature key", nameof(options));
                if (options.PublicKeySigningRequest is not null && !options.PublicKeySigningRequest.PublicKey.ID.SequenceEqual(options.PrivateKeys.SignatureKey.ID))
                    throw new ArgumentException("Public key signing request must sign the public signature key", nameof(options));
                if (options.Password is null && options.PrivateKeys.SymmetricKey is null) throw new ArgumentNullException(nameof(options), "Missing login password");
                if (options.PublicServerKeys is null) await GetPublicServerKeysAsync(stream, options, cancellationToken).DynamicContext();
                if (options.PublicServerKeys!.KeyExchangeKey is null) throw new ArgumentException("Missing server key exchange key", nameof(options));
                if (options.PublicServerKeys.SignatureKey is null) throw new ArgumentException("Missing server signature key", nameof(options));
                if (options.PublicServerKeys.KeyExchangeKey.Algorithm != options.PrivateKeys.KeyExchangeKey.Algorithm)
                    throw new ArgumentException("Key exchange algorithm mismatch", nameof(options));
                if (options.PublicServerKeys.KeyExchangeKey.Bits != options.PrivateKeys.KeyExchangeKey.Bits)
                    throw new ArgumentException("Key exchange key size mismatch", nameof(options));
                // Prepare signup
                hashOptions = options.HashOptions?.Clone() ?? HashHelper.GetDefaultOptions();
                hashOptions.LeaveOpen = true;
                pakeOptions = options.PakeOptions?.Clone() ?? Pake.DefaultOptions;
                cryptoOptions = options.CryptoOptions?.Clone() ?? Pake.DefaultCryptoOptions;
                cryptoOptions.LeaveOpen = true;
                pakeCryptoOptions = cryptoOptions.Clone();
                EncryptionAlgorithmBase encryption = EncryptionHelper.GetAlgorithm(cryptoOptions.Algorithm!);
                if (encryption.RequireMacAuthentication)
                    throw new ArgumentException("A cipher which requires MAC authentication isn't supported", nameof(options));
                symmetricKey = new SymmetricKeySuite(options.Password ?? options.PrivateKeys.SymmetricKey!.CloneArray(), options.Login, pakeOptions);
                stream.WriteByte((byte)AuthSequences.Signup);
                using MemoryPoolStream written = new()
                {
                    CleanReturned = true
                };
                using HubStream hub = new(stream, written)
                {
                    LeaveOpen = true
                };
                using HashStreams hash = HashHelper.GetAlgorithm(hashOptions.HashAlgorithm!).GetHashStream(hub, options: hashOptions);
                hash.Stream.WriteByte(VERSION);
                EncryptionStreams cipher = await StartEncryptionAsync(hash.Stream, options, encryption, cryptoOptions, cancellationToken).DynamicContext();
                try
                {
                    // Send the PAKE signup and get the new session key
                    PakeSignup signup;
                    using (Pake pake = new(symmetricKey, pakeOptions, pakeCryptoOptions))
                    {
                        authPayload = new AuthPayload(
                            options.Payload,
                            options.PrivateKeys.SignatureKey.ID,
                            options.PrivateKeys.SignedPublicKey is null
                                ? options.PrivateKeys.Public
                                : null,
                            options.PublicKeySigningRequest
                            );
                        signup = pake.CreateSignup(authPayload);
                        sessionKey = pake.SessionKey.CloneArray();
                    }
                    try
                    {
                        await cipher.CryptoStream.WriteSerializedAsync(signup, cancellationToken).DynamicContext();
                        cryptoOptions.Password = cryptoOptions.Password!.ExtendKey(sessionKey, options.PreSharedSecret);
                    }
                    finally
                    {
                        signup.Dispose();
                    }
                    await cipher.DisposeAsync().DynamicContext();
                    await hash.FinalizeHashAsync().DynamicContext();
                    Logging.WriteInfo($"CLIENT HASH {Convert.ToHexString(hash.Hash)}");//FIXME Hash different from the one the server computes - WTH!? (Written/red data is equal on client/server, hash on the server DOES match)
                    Logging.WriteInfo($"HUB HASH {Convert.ToHexString(written.ToArray().Hash(hashOptions))}");
                    cipher = await encryption.GetEncryptionStreamAsync(Stream.Null, stream, macStream: null, cryptoOptions, cancellationToken).DynamicContext();
                    // Sign the authentication and write the signature encrypted using the PAKE session key
                    await SignAuthSequenceAsync(cipher.CryptoStream, hash.Hash, options, hashOptions, SIGNUP_SIGNATURE_PURPOSE, cancellationToken).DynamicContext();
                    await stream.FlushAsync(cancellationToken).DynamicContext();
                }
                finally
                {
                    await cipher.DisposeAsync().DynamicContext();
                }
                // Get the server response
                await stream.FlushAsync(cancellationToken).DynamicContext();
                AuthSequences sequence = (AuthSequences)stream.ReadByte();
                switch (sequence)
                {
                    case AuthSequences.Signup:
                        break;
                    case AuthSequences.Error:
                        throw new UnauthorizedAccessException("The server denied the signup");
                    default:
                        throw new InvalidDataException($"Invalid server response sequence {sequence}");
                }
                DecryptionStreams decipher = await encryption.GetDecryptionStreamAsync(stream, Stream.Null, cryptoOptions, cancellationToken).DynamicContext();
                try
                {
                    // Exchange the PFS key
                    await ExtendEncryptionAsync(stream, decipher, encryption, options, cryptoOptions, cancellationToken).DynamicContext();
                    // Validate the server signature of the authentication sequence
                    await ValidateServerSignatureAsync(decipher.CryptoStream, options, AUTH_SIGNATURE_PURPOSE, hash.Hash, cancellationToken).DynamicContext();
                    // Get the signed public key
                    if (options.PublicKeySigningRequest is not null)
                    {
                        signedPublicKey = await decipher.CryptoStream.ReadSerializedAsync<AsymmetricSignedPublicKey>(cancellationToken: cancellationToken)
                            .DynamicContext();
                        if (!signedPublicKey.PublicKey.ID.SlowCompare(options.PrivateKeys.SignatureKey.ID))
                            throw new InvalidDataException("Signed key ID mismatch");
                        if (signedPublicKey.Signer is null) throw new InvalidDataException("Invalid self signed public key");
                        if (!signedPublicKey.Signer.PublicKey.ID.SlowCompare(options.PublicServerKeys.SignatureKey.ID))
                            throw new InvalidDataException("Signer public key mismatch");
                        if (signedPublicKey.CounterSigner is null)
                        {
                            if (options.PublicServerKeys.CounterSignatureKey is not null)
                                throw new InvalidDataException("Missing counter signer");
                        }
                        else
                        {
                            if (options.PublicServerKeys.CounterSignatureKey is null)
                                throw new InvalidDataException("Unexpected counter signature");
                            if (!signedPublicKey.CounterSigner.PublicKey.ID.SlowCompare(options.PublicServerKeys.CounterSignatureKey.ID))
                                throw new InvalidDataException("Counter signer key mismatch");
                        }
                        await signedPublicKey.ValidateAsync(cancellationToken: cancellationToken).DynamicContext();
                        options.PrivateKeys.SignedPublicKey = signedPublicKey;
                        signedPublicKey = null;
                    }
                }
                finally
                {
                    await decipher.DisposeAsync().DynamicContext();
                }
                return cryptoOptions.Password.CloneArray();
            }
            catch
            {
                sessionKey?.Clear();
                options.Login.Clear();
                options.Password?.Clear();
                signedPublicKey?.Dispose();
                symmetricKey?.Dispose();
                throw;
            }
            finally
            {
                options.PfsKeys?.Dispose();
                options.PreSharedSecret?.Clear();
                options.PublicKeySigningRequest?.Dispose();
                authPayload?.Clear();
                options.Payload?.Clear();
                hashOptions?.Clear();
                pakeOptions?.Clear();
                cryptoOptions?.Clear();
                pakeCryptoOptions?.Clear();
                if (disposeServerKey && options.PublicServerKeys is not null)
                {
                    options.PublicServerKeys.Dispose();
                    options.PublicServerKeys = null;
                }
            }
        }
    }
}
