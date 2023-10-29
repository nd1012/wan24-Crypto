using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
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
            IAsymmetricPublicKey? key = null;
            PublicKeySuite clientPfsKeys = new();
            try
            {
                key = (IAsymmetricPublicKey)Options.PrivateKeys!.KeyExchangeKey!.Algorithm.PublicKeyType.ConstructAuto();
                await key.DeserializeAsync(hash.Stream, StreamSerializer.Version, cancellationToken).DynamicContext();
                clientPfsKeys.KeyExchangeKey = key;
                context.CryptoOptions.Password = Options.PrivateKeys.KeyExchangeKey.DeriveKey(key);
                decipher = await Encryption!.GetDecryptionStreamAsync(hash.Stream, Stream.Null, context.CryptoOptions, cancellationToken).DynamicContext();
                if(Options.PrivateKeys.CounterKeyExchangeKey is not null)
                {
                    key = (IAsymmetricPublicKey)Options.PrivateKeys!.CounterKeyExchangeKey!.Algorithm.PublicKeyType.ConstructAuto();
                    await key.DeserializeAsync(hash.Stream, StreamSerializer.Version, cancellationToken).DynamicContext();
                    clientPfsKeys.CounterKeyExchangeKey = key;
                    context.CryptoOptions.Password = context.CryptoOptions.Password.ExtendKey(Options.PrivateKeys.CounterKeyExchangeKey.DeriveKey(key));
                    await decipher.DisposeAsync().DynamicContext();
                    decipher = await Encryption!.GetDecryptionStreamAsync(hash.Stream, Stream.Null, context.CryptoOptions, cancellationToken).DynamicContext();
                }
                key = null;
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
                key?.Dispose();
            }
        }

        /// <summary>
        /// Sign the authentication sequence
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cipher">Encryption streams</param>
        /// <param name="hash">Hash</param>
        /// <param name="purpose">Purpose</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private async Task SignAuthSequenceAsync(
            ServerAuthContext context, 
            EncryptionStreams cipher, 
            byte[] hash, 
            string purpose, 
            CancellationToken cancellationToken
            )
        {
            SignatureContainer signature = Options.PrivateKeys.SignatureKey!.SignHash(hash, purpose, context.HashOptions);
            await cipher.CryptoStream.WriteSerializedAsync(signature, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Extend the encryption key
        /// </summary>
        /// <param name="context">Context</param>
        /// <param name="cipher">Encryption streams</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Encryption streams</returns>
        private async Task<EncryptionStreams> ExtendEncryptionAsync(
            ServerAuthContext context, 
            EncryptionStreams cipher, 
            CancellationToken cancellationToken
            )
        {
            try
            {
                using (IKeyExchangePrivateKey pfsKey = CreatePfsKey())
                {
                    await pfsKey.PublicKey.SerializeAsync(cipher.CryptoStream, cancellationToken).DynamicContext();
                    context.CryptoOptions.Password = context.CryptoOptions.Password!.ExtendKey(pfsKey.DeriveKey(context.ClientPfsKeys!.KeyExchangeKey!));
                }
                await cipher.DisposeAsync().DynamicContext();
                cipher = await Encryption!.GetEncryptionStreamAsync(Stream.Null, context.Stream, macStream: null, context.CryptoOptions, cancellationToken).DynamicContext();
                if (Options.PrivateKeys.CounterKeyExchangeKey is not null)
                {
                    using IKeyExchangePrivateKey counterPfsKey = CreatePfsCounterKey();
                    await counterPfsKey.PublicKey.SerializeAsync(cipher.CryptoStream, cancellationToken).DynamicContext();
                    context.CryptoOptions.Password = context.CryptoOptions.Password!.ExtendKey(counterPfsKey.DeriveKey(context.ClientPfsKeys!.CounterKeyExchangeKey!));
                    await cipher.DisposeAsync().DynamicContext();
                    cipher = await Encryption!.GetEncryptionStreamAsync(Stream.Null, context.Stream, macStream: null, context.CryptoOptions, cancellationToken).DynamicContext();
                }
                return cipher;
            }
            catch
            {
                await cipher.DisposeAsync().DynamicContext();
                throw;
            }
        }

        /// <summary>
        /// Create a PFS key
        /// </summary>
        /// <returns>PFS key</returns>
        private IKeyExchangePrivateKey CreatePfsKey()
            => (IKeyExchangePrivateKey)(Options.PfsKeyPool is null
                ? Options.PrivateKeys.KeyExchangeKey!.Algorithm.CreateKeyPair(new()
                {
                    AsymmetricKeyBits = Options.PrivateKeys.KeyExchangeKey.Bits
                })
                : Options.PfsKeyPool.GetKey());

        /// <summary>
        /// Create a PFS counter key
        /// </summary>
        /// <returns>PFS key</returns>
        private IKeyExchangePrivateKey CreatePfsCounterKey()
            => (IKeyExchangePrivateKey)(Options.PfsCounterKeyPool is null
                ? Options.PrivateKeys.CounterKeyExchangeKey!.Algorithm.CreateKeyPair(new()
                {
                    AsymmetricKeyBits = Options.PrivateKeys.CounterKeyExchangeKey.Bits
                })
                : Options.PfsCounterKeyPool.GetKey());

        /// <summary>
        /// Set the matching and allowed MAC algorithm name for a PAKE authentication
        /// </summary>
        /// <param name="len">Digest length in byte</param>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        private CryptoOptions SetPakeMacAlgorithm(int len, CryptoOptions options)
            => options.MacAlgorithm is not null && MacHelper.GetAlgorithm(options.MacAlgorithm).MacLength == len
                ? options
                : options.WithMac(MacHelper.GetAlgorithmName(len, Options.AllowedMacAlgorithms), included: false);

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
        /// <param name="hash">Hash</param>
        /// <param name="decipher">Decryption streams</param>
        /// <param name="purpose">Expected signature purpose</param>
        /// <param name="cancellationToken">Cancellation token</param>
        private static async Task ValidateAuthSequenceAsync(
            ServerAuthContext context,
            byte[] hash,
            DecryptionStreams decipher,
            string purpose,
            CancellationToken cancellationToken
            )
        {
            SignatureContainer signature = await decipher.CryptoStream.ReadSerializedAsync<SignatureContainer>(cancellationToken: cancellationToken).DynamicContext();
            // Signature purpose must match
            if (signature.Purpose != purpose) throw new InvalidDataException("Invalid client signature purpose");
            // Signed hash must match
            if (!signature.SignedDataHash.SlowCompare(hash)) throw new InvalidDataException("Signed hash mismatch");
            // Signer must match
            using ISignaturePublicKey signerKey = signature.SignerPublicKey;
            if (
                !signerKey.ID.SlowCompare(context.PublicClientKeys!.SignatureKey!.ID) ||
                !signature.Signer.SlowCompare(context.PublicClientKeys.SignatureKey.ID)
                )
                throw new InvalidDataException("Signer key mismatch");
            // Counter signer must match
            if (context.PublicClientKeys.CounterSignatureKey is not null)
            {
                if (signature.CounterSignature is null || signature.CounterSignerPublicKeyData is null || signature.CounterSigner is null)
                    throw new InvalidDataException("Invalid counter signature configuration");
                using IAsymmetricPublicKey? signerCounterKey = signature.CounterSignerPublicKey;
                if (
                    !signerCounterKey!.ID.SlowCompare(context.PublicClientKeys.CounterSignatureKey.ID) ||
                    !signature.CounterSigner.SlowCompare(context.PublicClientKeys.CounterSignatureKey.ID)
                    )
                    throw new InvalidDataException("Counter signer key mismatch");
            }
            // Signature must be valid
            signerKey.ValidateSignature(signature);
        }
    }
}
