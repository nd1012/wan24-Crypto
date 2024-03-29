﻿using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    // Internals
    public static partial class ClientAuth
    {
        /// <summary>
        /// Get the pubic server keys
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private static async Task GetPublicServerKeysAsync(Stream stream, ClientAuthOptions options, CancellationToken cancellationToken)
        {
            stream.WriteByte((byte)AuthSequences.PublicKeyRequest);
            stream.WriteByte(VERSION);
            await stream.FlushAsync(cancellationToken).DynamicContext();
            AuthSequences sequence = (AuthSequences)await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
            switch (sequence)
            {
                case AuthSequences.PublicKeyRequest:
                    break;
                case AuthSequences.Error:
                    throw new UnauthorizedAccessException("The server denied the public key request");
                default:
                    throw new InvalidDataException($"Invalid server public key request response sequence {sequence}");
            }
            options.PublicServerKeys = await stream.ReadSerializedAsync<PublicKeySuite>(cancellationToken: cancellationToken).DynamicContext();
            options.PublicServerKeys.Signature?.ValidateSignedData(options.PublicServerKeys.CreateSignedData());
            if (options.ServerKeyValidator is not null && !await options.ServerKeyValidator(options.PublicServerKeys, cancellationToken).DynamicContext())
                throw new InvalidDataException("Failed to validate the server public key");
        }

        /// <summary>
        /// Start encryption
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="options">Options</param>
        /// <param name="encryption">Encryption algorithm</param>
        /// <param name="cryptoOptions">Options for encryption</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Encryption streams</returns>
        private static async Task<EncryptionStreams> StartEncryptionAsync(
            Stream stream,
            ClientAuthOptions options,
            EncryptionAlgorithmBase encryption,
            CryptoOptions cryptoOptions,
            CancellationToken cancellationToken
            )
        {
            cryptoOptions.ValidateAlgorithms();
            EncryptionStreams? cipher = null;
            PrivateKeySuite pfsKeys = new();
            try
            {
                pfsKeys.KeyExchangeKey = (IKeyExchangePrivateKey)options.PublicServerKeys!.KeyExchangeKey!.Algorithm.CreateKeyPair(new()
                {
                    AsymmetricKeyBits = options.PublicServerKeys.KeyExchangeKey.Bits
                });
                if (options.PublicServerKeys.CounterKeyExchangeKey is not null)
                    pfsKeys.CounterKeyExchangeKey = (IKeyExchangePrivateKey)options.PublicServerKeys!.CounterKeyExchangeKey!.Algorithm.CreateKeyPair(new()
                    {
                        AsymmetricKeyBits = options.PublicServerKeys.CounterKeyExchangeKey.Bits
                    });
                await stream.WriteSerializedAsync(pfsKeys.KeyExchangeKey.PublicKey, cancellationToken).DynamicContext();
                cryptoOptions.SetNewPassword(pfsKeys.KeyExchangeKey.DeriveKey(options.PublicServerKeys.KeyExchangeKey));
                cipher = await encryption.GetEncryptionStreamAsync(Stream.Null, stream, macStream: null, cryptoOptions, cancellationToken).DynamicContext();
                if (options.PublicServerKeys.CounterKeyExchangeKey is not null)
                {
                    await stream.WriteSerializedAsync(pfsKeys.CounterKeyExchangeKey!.PublicKey, cancellationToken).DynamicContext();
                    cryptoOptions.Password = cryptoOptions.Password.ExtendKey(pfsKeys.CounterKeyExchangeKey.DeriveKey(options.PublicServerKeys.CounterKeyExchangeKey));
                    await cipher.DisposeAsync().DynamicContext();
                    cipher = await encryption.GetEncryptionStreamAsync(Stream.Null, stream, macStream: null, cryptoOptions, cancellationToken).DynamicContext();
                }
                options.PfsKeys = pfsKeys;
                return cipher;
            }
            catch
            {
                pfsKeys.Dispose();
                if (cipher is not null) await cipher.DisposeAsync().DynamicContext();
                throw;
            }
        }

        /// <summary>
        /// Sign the authentication sequence
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="hash">Hash</param>
        /// <param name="options">Options</param>
        /// <param name="hashOptions">Hash options</param>
        /// <param name="purpose">Signature purpose</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private static async Task SignAuthSequenceAsync(
            Stream stream,
            byte[] hash,
            ClientAuthOptions options,
            CryptoOptions hashOptions,
            string purpose,
            CancellationToken cancellationToken
            )
        {
            hashOptions.ValidateAlgorithms();
            SignatureContainer signature = options.PrivateKeys.SignatureKey!.SignHash(hash, purpose, hashOptions);
            await stream.WriteSerializedAsync(signature, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Extend the encryption
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="decipher">Decryption streams</param>
        /// <param name="encryption">Encryption algorithm</param>
        /// <param name="options">Options</param>
        /// <param name="cryptoOptions">Options for encryption</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>New decryption streams</returns>
        private static async Task<DecryptionStreams> ExtendEncryptionAsync(
            Stream stream,
            DecryptionStreams decipher,
            EncryptionAlgorithmBase encryption,
            ClientAuthOptions options,
            CryptoOptions cryptoOptions,
            CancellationToken cancellationToken
            )
        {
            cryptoOptions.ValidateAlgorithms();
            IAsymmetricPublicKey key = (IAsymmetricPublicKey)options.PublicServerKeys!.KeyExchangeKey!.Algorithm.PublicKeyType.ConstructAuto();
            try
            {
                await key.DeserializeAsync(decipher.CryptoStream, StreamSerializer.Version, cancellationToken).DynamicContext();
                cryptoOptions.Password = cryptoOptions.Password!.ExtendKey(options.PfsKeys!.KeyExchangeKey!.DeriveKey(key));
                await decipher.DisposeAsync().DynamicContext();
                decipher = await encryption.GetDecryptionStreamAsync(stream, Stream.Null, cryptoOptions, cancellationToken).DynamicContext();
                if (options.PublicServerKeys.CounterKeyExchangeKey is not null)
                {
                    key.Dispose();
                    key = (IAsymmetricPublicKey)options.PublicServerKeys!.KeyExchangeKey!.Algorithm.PublicKeyType.ConstructAuto();
                    await key.DeserializeAsync(decipher.CryptoStream, StreamSerializer.Version, cancellationToken).DynamicContext();
                    cryptoOptions.Password = cryptoOptions.Password!.ExtendKey(options.PfsKeys!.CounterKeyExchangeKey!.DeriveKey(key));
                    await decipher.DisposeAsync().DynamicContext();
                    decipher = await encryption.GetDecryptionStreamAsync(stream, Stream.Null, cryptoOptions, cancellationToken).DynamicContext();
                }
                return decipher;
            }
            finally
            {
                options.PfsKeys!.Dispose();
                options.PfsKeys = null;
                key.Dispose();
            }
        }

        /// <summary>
        /// Validate the server signature
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="options">Options</param>
        /// <param name="purpose">Signature purpose</param>
        /// <param name="signedHash">Signed hash</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private static async Task ValidateServerSignatureAsync(
            Stream stream,
            ClientAuthOptions options,
            string purpose,
            byte[] signedHash,
            CancellationToken cancellationToken
            )
        {
            SignatureContainer signature = await stream.ReadSerializedAsync<SignatureContainer>(cancellationToken: cancellationToken).DynamicContext();
            // Signature purpose must match
            if (signature.Purpose != purpose) throw new InvalidDataException("Invalid server signature purpose");
            // Signed hash must match
            if (!signature.SignedDataHash.SlowCompare(signedHash)) throw new InvalidDataException("Signed hash mismatch");
            // Signer must match
            using ISignaturePublicKey signerKey = signature.SignerPublicKey;
            if (
                !signerKey.ID.SlowCompare(options.PublicServerKeys!.SignatureKey!.ID) ||
                !signature.Signer.SlowCompare(options.PublicServerKeys.SignatureKey.ID)
                )
                throw new InvalidDataException("Signer key mismatch");
            // Counter signer must match
            if (options.PublicServerKeys.CounterSignatureKey is not null)
            {
                if (signature.CounterSignature is null || signature.CounterSignerPublicKeyData is null || signature.CounterSigner is null)
                    throw new InvalidDataException("Invalid counter signature configuration");
                using IAsymmetricPublicKey? signerCounterKey = signature.CounterSignerPublicKey;
                if (
                    !signerCounterKey!.ID.SlowCompare(options.PublicServerKeys.CounterSignatureKey.ID) ||
                    !signature.CounterSigner.SlowCompare(options.PublicServerKeys.CounterSignatureKey.ID)
                    )
                    throw new InvalidDataException("Counter signer key mismatch");
            }
            // Signature must be valid
            signerKey.ValidateSignature(signature);
        }
    }
}
