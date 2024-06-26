﻿using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    // Authentication
    public static partial class ClientAuth
    {
        /// <summary>
        /// Authenticate
        /// </summary>
        /// <param name="stream">Stream (requires blocking)</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PFS session key (should be cleared!)</returns>
        public static async Task<byte[]> AuthenticateAsync(
            this Stream stream,
            ClientAuthOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            options ??= ClientAuthOptions.DefaultOptions ?? throw new ArgumentNullException(nameof(options));
            bool disposeServerKey = options.PublicServerKeys is null;
            ISymmetricKeySuite? symmetricKey = null;
            byte[]? authPayload = null,
                sessionKey = null;
            CryptoOptions? hashOptions = null,
                pakeOptions = null,
                cryptoOptions = null,
                pakeCryptoOptions = null;
            try
            {
                // Ensure valid parameters
                if (options.PrivateKeys.KeyExchangeKey is null) throw new ArgumentException("Missing private key exchange key", nameof(options));
                if (options.PrivateKeys.SignatureKey is null) throw new ArgumentException("Missing private signature key", nameof(options));
                if (options.Password is null && options.PrivateKeys.SymmetricKey is null && options.SymmetricKey is null)
                    throw new ArgumentNullException(nameof(options), "Missing login password");
                if (options.PublicServerKeys is null) await GetPublicServerKeysAsync(stream, options, cancellationToken).DynamicContext();
                if (options.PublicServerKeys!.KeyExchangeKey is null) throw new ArgumentException("Missing server key exchange key", nameof(options));
                if (options.PublicServerKeys.SignatureKey is null) throw new ArgumentException("Missing server signature key", nameof(options));
                if (options.PublicServerKeys.KeyExchangeKey.Algorithm != options.PrivateKeys.KeyExchangeKey.Algorithm)
                    throw new ArgumentException("Key exchange algorithm mismatch", nameof(options));
                if (options.PublicServerKeys.KeyExchangeKey.Bits != options.PrivateKeys.KeyExchangeKey.Bits)
                    throw new ArgumentException("Key exchange key size mismatch", nameof(options));
                // Prepare authentication
                hashOptions = options.HashOptions?.GetCopy() ?? HashHelper.GetDefaultOptions();
                hashOptions.ApplyPrivateKeySuite(options.PrivateKeys, forSignature: true);
                hashOptions.LeaveOpen = true;
                hashOptions.ValidateAlgorithms();
                pakeOptions = options.PakeOptions?.GetCopy() ?? Pake.DefaultOptions;
                pakeOptions.ValidateAlgorithms();
                cryptoOptions = options.CryptoOptions?.GetCopy() ?? Pake.DefaultCryptoOptions;
                cryptoOptions.ValidateAlgorithms();
                cryptoOptions.LeaveOpen = true;
                pakeCryptoOptions = cryptoOptions.GetCopy();
                EncryptionAlgorithmBase encryption = EncryptionHelper.GetAlgorithm(cryptoOptions.Algorithm!);
                if (encryption.RequireMacAuthentication)
                    throw new ArgumentException("A cipher which requires MAC authentication isn't supported", nameof(options));
                symmetricKey = options.SymmetricKey ?? new SymmetricKeySuite(options.Password ?? options.PrivateKeys.SymmetricKey!.CloneArray(), options.Login, pakeOptions);
                stream.WriteByte((byte)AuthSequences.Authentication);
                using HashStreams hash = HashHelper.GetAlgorithm(hashOptions.HashAlgorithm!).GetHashStream(stream, options: hashOptions);
                hash.Stream.WriteByte(VERSION);
                EncryptionStreams cipher = await StartEncryptionAsync(hash.Stream, options, encryption, cryptoOptions, cancellationToken).DynamicContext();
                try
                {
                    // Send the PAKE authentication and get the new session key
                    PakeAuth auth;
                    authPayload = new AuthPayload(options.Payload);
                    if (options.FastPakeAuth is null)
                    {
                        using Pake pake = new(symmetricKey, pakeOptions, pakeCryptoOptions);
                        symmetricKey = null;
                        auth = pake.CreateAuth(authPayload, options.EncryptPayload, options.PayloadFactory);
                        sessionKey = pake.SessionKey.CloneArray();
                    }
                    else
                    {
                        (auth, sessionKey) = await options.FastPakeAuth.CreateAuthAsync(authPayload, options.EncryptPayload).DynamicContext();
                    }
                    try
                    {
                        await cipher.CryptoStream.WriteSerializedAsync(auth, cancellationToken).DynamicContext();
                        cryptoOptions.Password = cryptoOptions.Password!.ExtendKey(sessionKey);
                        sessionKey = null;
                    }
                    finally
                    {
                        auth.Dispose();
                    }
                    await cipher.DisposeAsync().DynamicContext();
                    await hash.FinalizeHashAsync().DynamicContext();
                    cipher = await encryption.GetEncryptionStreamAsync(Stream.Null, stream, macStream: null, cryptoOptions, cancellationToken).DynamicContext();
                    // Sign the authentication and write the signature encrypted using the PAKE session key
                    await SignAuthSequenceAsync(cipher.CryptoStream, hash.Hash, options, hashOptions, AUTH_SIGNATURE_PURPOSE, cancellationToken).DynamicContext();
                }
                finally
                {
                    await cipher.DisposeAsync().DynamicContext();
                }
                // Get the server response
                await stream.FlushAsync(cancellationToken).DynamicContext();
                if (!options.GetAuthenticationResponse) return cryptoOptions.Password.CloneArray();
                AuthSequences sequence = (AuthSequences)await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                switch (sequence)
                {
                    case AuthSequences.Authentication:
                        break;
                    case AuthSequences.Error:
                        throw new UnauthorizedAccessException("The server denied the authentication");
                    default:
                        throw new InvalidDataException($"Invalid server response sequence {sequence}");
                }
                DecryptionStreams decipher = await encryption.GetDecryptionStreamAsync(stream, Stream.Null, cryptoOptions, cancellationToken).DynamicContext();
                try
                {
                    // Extend the encryption
                    decipher = await ExtendEncryptionAsync(stream, decipher, encryption, options, cryptoOptions, cancellationToken).DynamicContext();
                    // Validate the server signature of the authentication sequence
                    await ValidateServerSignatureAsync(decipher.CryptoStream, options, AUTH_SIGNATURE_PURPOSE, hash.Hash, cancellationToken).DynamicContext();
                }
                finally
                {
                    await decipher.DisposeAsync().DynamicContext();
                }
                return cryptoOptions.Password.CloneArray();
            }
            catch
            {
                options.Login?.Clear();
                options.Password?.Clear();
                sessionKey?.Clear();
                symmetricKey?.Dispose();
                throw;
            }
            finally
            {
                if (options.PfsKeys is not null)
                {
                    options.PfsKeys.Dispose();
                    options.PfsKeys = null;
                }
                options.Payload?.Clear();
                authPayload?.Clear();
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
