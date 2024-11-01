﻿using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Asymmetric public key signing request
    /// </summary>
    public sealed record class AsymmetricPublicKeySigningRequest : DisposableStreamSerializerRecordBase
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Signed data
        /// </summary>
        private byte[]? SignedData = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricPublicKeySigningRequest() : base(VERSION) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key (will be copied)</param>
        /// <param name="attributes">Attributes</param>
        /// <param name="purpose">Request purpose (used for signing the request)</param>
        /// <param name="options">Options (if a private signature key of the given public key is included, this request will be signed)</param>
        public AsymmetricPublicKeySigningRequest(IAsymmetricPublicKey publicKey, Dictionary<string, string>? attributes = null, string? purpose = null, CryptoOptions? options = null)
            : this()
        {
            PublicKey = publicKey.GetCopy();
            if (attributes is not null) Attributes.AddRange(attributes);
            if (options?.PrivateKey is not ISignaturePrivateKey signatureKey || !signatureKey.ID.SequenceEqual(publicKey.ID)) return;
            Signature = signatureKey.SignData(CreateSignedData(), purpose, options);
        }

        /// <summary>
        /// Public key (will be disposed)
        /// </summary>
        public IAsymmetricPublicKey PublicKey { get; set; } = null!;

        /// <summary>
        /// Attributes
        /// </summary>
        [CountLimit(byte.MaxValue)]
        [ItemStringLength(byte.MaxValue, ItemValidationTargets.Key)]
        [ItemStringLength(byte.MaxValue)]
        public Dictionary<string, string> Attributes { get; private set; } = [];

        /// <summary>
        /// Signature
        /// </summary>
        public SignatureContainer? Signature { get; private set; }

        /// <summary>
        /// Sign the request
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="options">Options</param>
        public void SignRequest(ISignaturePrivateKey privateKey, CryptoOptions? options = null)
        {
            EnsureUndisposed();
            Signature = privateKey.SignData(CreateSignedData(), options: options);
        }

        /// <summary>
        /// Validate the signing request signature
        /// </summary>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <returns>If the signature is valid</returns>
        public bool ValidateRequestSignature(bool throwOnError = true)
        {
            EnsureUndisposed();
            if (Signature is null) throw new InvalidOperationException();
            using ISignaturePublicKey publicKey = Signature.SignerPublicKey;
            return publicKey.ValidateSignature(Signature, CreateSignedData(), throwOnError);
        }

        /// <summary>
        /// Get as unsigned key (a signed request will be validated)
        /// </summary>
        /// <returns>Unsigned key (don't forget to dispose)</returns>
        public AsymmetricSignedPublicKey GetAsUnsignedKey()
        {
            EnsureUndisposed();
            this.ValidateObject();
            if (Signature is not null)
            {
                using (ISignaturePublicKey signer = Signature.SignerPublicKey)
                    signer.ValidateSignature(Signature, CreateSignedData());
                if (Signature.CounterSignature is not null) HybridAlgorithmHelper.ValidateCounterSignature(Signature);
            }
            return new(PublicKey, Attributes);
        }

        /// <summary>
        /// Create the signed data
        /// </summary>
        /// <returns>Signed data</returns>
        public byte[] CreateSignedData()
        {
            try
            {
                EnsureUndisposed();
                if (SignedData is not null) return SignedData;
                using MemoryStream ms = new();
                ms.WriteSerializerVersion()
                    .WriteNumber(VERSION)
                    .WriteBytes(PublicKey.Export())
                    .WriteDict(Attributes);
                SignedData = ms.ToArray();
                return SignedData;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => PublicKey.Dispose();

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteBytesNullable(SignedData);
            if (SignedData is null)
            {
                stream.WriteAny(PublicKey)
                    .WriteDict(Attributes);
            }
            else
            {
                stream.WriteSerialized(Signature!);
            }
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            stream.WriteBytesNullable(SignedData);
            if (SignedData is null)
            {
                await stream.WriteAnyAsync(PublicKey, cancellationToken).DynamicContext();
                await stream.WriteDictAsync(Attributes, cancellationToken).DynamicContext();
            }
            else
            {
                stream.WriteSerialized(Signature!);
            }
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            SignedData = stream.ReadArrayNullable<byte>(version, minLen: 1, maxLen: AsymmetricKeyBase.MaxArrayLength);
            if (SignedData is null)
            {
                PublicKey = stream.ReadAny(version) as IAsymmetricPublicKey ?? throw new SerializerException("Failed to deserialize the public key");
                Attributes = stream.ReadDict<string, string>(version, maxLen: byte.MaxValue);
            }
            else
            {
                DeserializeSignedData();
                Signature = stream.ReadSerialized<SignatureContainer>(version);
            }
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            SignedData = await stream.ReadArrayNullableAsync<byte>(version, minLen: 1, maxLen: AsymmetricKeyBase.MaxArrayLength, cancellationToken: cancellationToken).DynamicContext();
            if (SignedData is null)
            {
                PublicKey = await stream.ReadAnyAsync(version, cancellationToken: cancellationToken).DynamicContext() as IAsymmetricPublicKey ?? 
                    throw new SerializerException("Failed to deserialize the public key");
                Attributes = await stream.ReadDictAsync<string, string>(version, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            }
            else
            {
                DeserializeSignedData();
                Signature = await stream.ReadSerializedAsync<SignatureContainer>(version, cancellationToken).DynamicContext();
            }
        }

        /// <summary>
        /// Deserialize the signed data
        /// </summary>
        private void DeserializeSignedData()
        {
            EnsureUndisposed();
            if (SignedData is null) throw new InvalidOperationException();
            using MemoryStream ms = new(SignedData);
            int ssv = ms.ReadSerializerVersion(),
                ov = ms.ReadNumber<int>();
            if (ov < 1 || ov > VERSION) throw new SerializerException($"Invalid object version {ov}", new InvalidDataException());
            IAsymmetricPublicKey? key = null;
            using RentedMemory<byte> keyData = ms.ReadMemory(ssv, minLen: 1, maxLen: AsymmetricKeyBase.MaxArrayLength) 
                ?? throw CryptographicException.From(new InvalidDataException("Empty key data"));
            byte[] keyDataArr = keyData.Memory.ToArray();
            try
            {
                key = AsymmetricKeyBase.Import<IAsymmetricPublicKey>(keyDataArr);
                PublicKey = key;
            }
            catch
            {
                key?.Dispose();
                if (!keyData.Clear) keyData.Memory.Span.Clean();
                keyDataArr.Clear();
                throw;
            }
            Attributes = ms.ReadDict<string, string>(ssv, maxLen: byte.MaxValue);
        }

        /// <summary>
        /// Cast as unsigned public key
        /// </summary>
        /// <param name="signingRequest">Signing request</param>
        public static implicit operator AsymmetricSignedPublicKey(AsymmetricPublicKeySigningRequest signingRequest) => signingRequest.GetAsUnsignedKey();

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="request">Request</param>
        public static implicit operator byte[](AsymmetricPublicKeySigningRequest request) => request.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricPublicKeySigningRequest(byte[] data) => data.ToObject<AsymmetricPublicKeySigningRequest>();
    }
}
