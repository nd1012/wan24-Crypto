﻿using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
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
            AsymmetricSignedPublicKey? signedPublicKey = null;
            try
            {
                // Ensure valid parameters
                if (options.PrivateKeys.KeyExchangeKey is null) throw new ArgumentException("Missing private key exchange key", nameof(options));
                if (options.PrivateKeys.SignatureKey is null) throw new ArgumentException("Missing private signature key", nameof(options));
                if (options.PublicKeySigningRequest is not null && !options.PublicKeySigningRequest.PublicKey.ID.SequenceEqual(options.PrivateKeys.SignatureKey.ID))
                    throw new ArgumentException("Public key signing request must sign the public signature key", nameof(options));
                if (options.Password is null && options.PrivateKeys.SymmetricKey is null && options.SymmetricKey is null)
                    throw new ArgumentNullException(nameof(options), "Missing login password");
                if (options.PublicServerKeys is null) await GetPublicServerKeysAsync(stream, options, cancellationToken).DynamicContext();
                if (options.PublicServerKeys!.KeyExchangeKey is null) throw new ArgumentException("Missing server key exchange key", nameof(options));
                if (options.PublicServerKeys.SignatureKey is null) throw new ArgumentException("Missing server signature key", nameof(options));
                if (options.PublicServerKeys.KeyExchangeKey.Algorithm != options.PrivateKeys.KeyExchangeKey.Algorithm)
                    throw new ArgumentException("Key exchange algorithm mismatch", nameof(options));
                if (options.PublicServerKeys.KeyExchangeKey.Bits != options.PrivateKeys.KeyExchangeKey.Bits)
                    throw new ArgumentException("Key exchange key size mismatch", nameof(options));
                // Prepare signup
                hashOptions = options.HashOptions?.GetCopy() ?? HashHelper.GetDefaultOptions();
                hashOptions.LeaveOpen = true;
                hashOptions.ApplyPrivateKeySuite(options.PrivateKeys, forSignature: true);
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
                stream.WriteByte((byte)AuthSequences.Signup);
                using HashStreams hash = HashHelper.GetAlgorithm(hashOptions.HashAlgorithm!).GetHashStream(stream, options: hashOptions);
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
                        signup = pake.CreateSignup(authPayload, options.PayloadFactory);
                        sessionKey = pake.SessionKey.CloneArray();
                    }
                    symmetricKey = null;
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
                AuthSequences sequence = (AuthSequences)await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
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
                    decipher = await ExtendEncryptionAsync(stream, decipher, encryption, options, cryptoOptions, cancellationToken).DynamicContext();
                    // Validate the server signature of the authentication sequence
                    await ValidateServerSignatureAsync(decipher.CryptoStream, options, SIGNUP_SIGNATURE_PURPOSE, hash.Hash, cancellationToken).DynamicContext();
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
                        if (signedPublicKey.Signature.CounterSignature is null)
                        {
                            if (options.PublicServerKeys.CounterSignatureKey is not null)
                                throw new InvalidDataException("Missing counter signer");
                        }
                        else
                        {
                            if (options.PublicServerKeys.CounterSignatureKey is null)
                                throw new InvalidDataException("Unexpected counter signature");
                            if (signedPublicKey.Signature.CounterSigner is null)
                                throw new InvalidDataException("Missing counter signer public key ID");
                            if (!signedPublicKey.Signature.CounterSigner.SlowCompare(options.PublicServerKeys.CounterSignatureKey.ID))
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
                options.Login?.Clear();
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
