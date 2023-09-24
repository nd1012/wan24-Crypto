using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Networking
{
    // Internals
    public sealed partial class ServerAuth
    {
        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Options.PrivateKeys.Dispose();
            Options.HashOptions?.Clear();
            Options.PakeOptions?.Clear();
            Options.CryptoOptions?.Clear();
        }

        /// <summary>
        /// Start decryption
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="hash">Hash streams</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Encryption streams</returns>
        private async Task<DecryptionStreams> StartDecryptionAsync(ServerAuthContext context, HashStreams hash, CancellationToken cancellationToken)
        {
            DecryptionStreams? decipher = null;
            byte[]? keyData = null;
            PublicKeySuite clientPfsKeys = new();
            try
            {
                keyData = (await hash.Stream.ReadBytesAsync(minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                clientPfsKeys.KeyExchangeKey = Options.PrivateKeys.KeyExchangeKey!.Algorithm.DeserializePublicKey(keyData.CloneArray());
                context.CryptoOptions.Password = Options.PrivateKeys.KeyExchangeKey.DeriveKey(clientPfsKeys.KeyExchangeKey);
                decipher = await Encryption!.GetDecryptionStreamAsync(hash.Stream, Stream.Null, context.CryptoOptions, cancellationToken).DynamicContext();
                if(Options.PrivateKeys.CounterKeyExchangeKey is not null)
                {
                    keyData.Clear();
                    keyData = (await hash.Stream.ReadBytesAsync(minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                    clientPfsKeys.CounterKeyExchangeKey = Options.PrivateKeys.CounterKeyExchangeKey!.Algorithm.DeserializePublicKey(keyData.CloneArray());
                    context.CryptoOptions.Password = context.CryptoOptions.Password.ExtendKey(Options.PrivateKeys.CounterKeyExchangeKey.DeriveKey(clientPfsKeys.CounterKeyExchangeKey));
                    await decipher.DisposeAsync().DynamicContext();
                    decipher = await Encryption!.GetDecryptionStreamAsync(hash.Stream, Stream.Null, context.CryptoOptions, cancellationToken).DynamicContext();
                }
                context.ClientPfsKeys = clientPfsKeys;
                return decipher;
            }
            catch
            {
                clientPfsKeys.Dispose();
                if (decipher is not null) await decipher.DisposeAsync().DynamicContext();
                throw;
            }
            finally
            {
                keyData?.Clear();
            }
        }

        /// <summary>
        /// Sign the authentication sequence
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cipher">Encryption streams</param>
        /// <param name="signedHash">Signed hash</param>
        /// <param name="purpose">Purpose</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private async Task SignAuthSequenceAsync(
            ServerAuthContext context, 
            EncryptionStreams cipher, 
            byte[] signedHash, 
            string purpose, 
            CancellationToken cancellationToken
            )
        {
            SignatureContainer signature = Options.PrivateKeys.SignatureKey!.SignHash(signedHash.CloneArray(), purpose, context.HashOptions);
            context.Stream.WriteByte((byte)(context.Authentication is null ? AuthSequences.Signup : AuthSequences.Authentication));
            await cipher.CryptoStream.WriteSerializedAsync(signature, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Extend the encryption key
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cipher">Encryption streams</param>
        /// <param name="returnCipher">Return new encryption streams?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Encryption streams</returns>
        private async Task<EncryptionStreams?> ExtendEncryptionAsync(
            ServerAuthContext context, 
            EncryptionStreams cipher, 
            bool returnCipher,
            CancellationToken cancellationToken
            )
        {
            try
            {
                using (IKeyExchangePrivateKey pfsKey = (IKeyExchangePrivateKey)Options.PrivateKeys.KeyExchangeKey!.Algorithm.CreateKeyPair(new()
                {
                    AsymmetricKeyBits = Options.PrivateKeys.KeyExchangeKey.Bits
                }))
                {
                    await cipher.CryptoStream.WriteBytesAsync(pfsKey.PublicKey.KeyData.Array, cancellationToken).DynamicContext();
                    context.CryptoOptions.Password = context.CryptoOptions.Password!.ExtendKey(pfsKey.DeriveKey(context.ClientPfsKeys!.KeyExchangeKey!));
                }
                await cipher.DisposeAsync().DynamicContext();
                if (returnCipher || Options.PrivateKeys.CounterKeyExchangeKey is not null)
                    cipher = await Encryption!.GetEncryptionStreamAsync(Stream.Null, context.Stream, macStream: null, context.CryptoOptions, cancellationToken).DynamicContext();
                if (Options.PrivateKeys.CounterKeyExchangeKey is not null)
                {
                    using IKeyExchangePrivateKey counterPfsKey = (IKeyExchangePrivateKey)Options.PrivateKeys.CounterKeyExchangeKey!.Algorithm.CreateKeyPair(new()
                    {
                        AsymmetricKeyBits = Options.PrivateKeys.CounterKeyExchangeKey.Bits
                    });
                    await cipher.CryptoStream.WriteBytesAsync(counterPfsKey.PublicKey.KeyData.Array, cancellationToken).DynamicContext();
                    context.CryptoOptions.Password = context.CryptoOptions.Password!.ExtendKey(counterPfsKey.DeriveKey(context.ClientPfsKeys!.CounterKeyExchangeKey!));
                    await cipher.DisposeAsync().DynamicContext();
                    if (returnCipher)
                        cipher = await Encryption!.GetEncryptionStreamAsync(Stream.Null, context.Stream, macStream: null, context.CryptoOptions, cancellationToken)
                            .DynamicContext();
                }
                return returnCipher ? cipher : null;
            }
            catch
            {
                await cipher.DisposeAsync().DynamicContext();
                throw;
            }
        }

        /// <summary>
        /// Validate the protocol version
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private static async Task ValidateProtocolVersionAsync(Stream stream, CancellationToken cancellationToken)
        {
            int version = await stream.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
            if (version != 1) throw new InvalidDataException($"Invalid/unsupported protocol version {version}");
        }

        /// <summary>
        /// Validate the authentication sequence signature
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="hash">Hash streams</param>
        /// <param name="decipher">Decryption streams</param>
        /// <param name="purpose">Expected signature purpose</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private static async Task ValidateAuthSequenceAsync(
            ServerAuthContext context,
            HashStreams hash,
            DecryptionStreams decipher,
            string purpose,
            CancellationToken cancellationToken
            )
        {
            hash.Stream.Dispose();
            hash.Transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            Logging.WriteInfo($"HASH2 {Convert.ToHexString(hash.Transform.Hash!)}");
            SignatureContainer signature = await decipher.CryptoStream.ReadSerializedAsync<SignatureContainer>(cancellationToken: cancellationToken).DynamicContext();
            // Signature purpose must match
            if (signature.Purpose != purpose) throw new InvalidDataException("Invalid client signature purpose");
            // Signed hash must match
            if (!signature.SignedDataHash.SlowCompare(hash.Transform.Hash!)) throw new InvalidDataException("Signed hash mismatch");
            // Signer must match
            if (
                !signature.SignerPublicKey.ID.SlowCompare(context.PublicClientKeys!.SignatureKey!.ID) ||
                !signature.Signer.SlowCompare(context.PublicClientKeys.SignatureKey.ID)
                )
                throw new InvalidDataException("Signer key mismatch");
            // Counter signer must match
            if (context.PublicClientKeys.CounterSignatureKey is not null)
            {
                if (signature.CounterSignature is null || signature.CounterSignerPublicKeyData is null || signature.CounterSigner is null)
                    throw new InvalidDataException("Invalid counter signature configuration");
                if (
                    !signature.CounterSignerPublicKey!.ID.SlowCompare(context.PublicClientKeys.CounterSignatureKey.ID) ||
                    !signature.CounterSigner.SlowCompare(context.PublicClientKeys.CounterSignatureKey.ID)
                    )
                    throw new InvalidDataException("Counter signer key mismatch");
            }
            // Signature must be valid
            signature.SignerPublicKey.ValidateSignature(signature);
        }
    }
}
