using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Signature container
    /// </summary>
    public sealed class SignatureContainer : StreamSerializerBase, ICloneable
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;
        /// <summary>
        /// Nonce length in bytes
        /// </summary>
        public const int NONCE_LENGTH = 20;

        /// <summary>
        /// Signed data
        /// </summary>
        private byte[]? SignedData = null;
        /// <summary>
        /// Counter signed data
        /// </summary>
        private byte[]? CounterSignedData = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public SignatureContainer() : base(VERSION) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm name</param>
        /// <param name="signedDataHash">Signed data hash</param>
        /// <param name="signer">Signer</param>
        /// <param name="counterSigner">Counter signer</param>
        /// <param name="purpose">Signature purpose</param>
        public SignatureContainer(
            string hashAlgorithm,
            byte[] signedDataHash,
            ISignaturePrivateKey signer,
            ISignaturePrivateKey? counterSigner,
            string? purpose
            ) : this()
        {
            HashAlgorithm = hashAlgorithm;
            AsymmetricAlgorithm = signer.Algorithm.Name;
            AsymmetricCounterAlgorithm = counterSigner?.Algorithm.Name;
            SignedDataHash = signedDataHash;
            Signer = signer.ID;
            SignerPublicKeyData = signer.PublicKey.KeyData.Array.CloneArray();
            CounterSigner = counterSigner?.ID;
            CounterSignerPublicKeyData = (byte[]?)counterSigner?.PublicKey.KeyData.Array.Clone();
            Purpose = purpose;
        }

        /// <summary>
        /// Signed time (UTC)
        /// </summary>
        public DateTime Signed { get; private set; }

        /// <summary>
        /// Hash algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string HashAlgorithm { get; private set; } = null!;

        /// <summary>
        /// Asymmetric algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string AsymmetricAlgorithm { get; private set; } = null!;

        /// <summary>
        /// Asymmetric counter algorithm name
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? AsymmetricCounterAlgorithm { get; private set; }

        /// <summary>
        /// Signed data hash
        /// </summary>
        [CountLimit(HashMd5Algorithm.HASH_LENGTH, byte.MaxValue)]
        public byte[] SignedDataHash { get; private set; } = null!;

        /// <summary>
        /// Nonce
        /// </summary>
        [CountLimit(NONCE_LENGTH, NONCE_LENGTH)]
        public byte[]? Nonce { get; private set; } = null!;

        /// <summary>
        /// Signature (signs all data except the counter signature)
        /// </summary>
        [CountLimit(1, ushort.MaxValue)]
        public byte[] Signature { get; set; } = null!;

        /// <summary>
        /// Counter signature (signs all data including the signature)
        /// </summary>
        [CountLimit(1, ushort.MaxValue), RequiredIf(nameof(AsymmetricCounterAlgorithm))]
        public byte[]? CounterSignature { get; set; }

        /// <summary>
        /// Signer
        /// </summary>
        [CountLimit(HashMd5Algorithm.HASH_LENGTH, byte.MaxValue)]
        public byte[] Signer { get; private set; } = null!;

        /// <summary>
        /// Counter signer
        /// </summary>
        [CountLimit(HashMd5Algorithm.HASH_LENGTH, byte.MaxValue), RequiredIf(nameof(CounterSignature))]
        public byte[]? CounterSigner { get; private set; }

        /// <summary>
        /// Signer public key data
        /// </summary>
        [CountLimit(1, ushort.MaxValue)]
        public byte[] SignerPublicKeyData { get; private set; } = null!;

        /// <summary>
        /// Counter signer public key data
        /// </summary>
        [CountLimit(1, ushort.MaxValue), RequiredIf(nameof(CounterSigner))]
        public byte[]? CounterSignerPublicKeyData { get; private set; }

        /// <summary>
        /// Signer public key (don't forget to dispose!)
        /// </summary>
        public ISignaturePublicKey SignerPublicKey
        {
            get
            {
                try
                {
                    IAsymmetricPublicKey res = AsymmetricHelper.GetAlgorithm(AsymmetricAlgorithm).DeserializePublicKey(SignerPublicKeyData.CloneArray());
                    try
                    {
                        return (ISignaturePublicKey)res;
                    }
                    catch
                    {
                        res.Dispose();
                        throw;
                    }
                }
                catch (CryptographicException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

        /// <summary>
        /// Counter signer public key (don't forget to dispose!)
        /// </summary>
        public ISignaturePublicKey? CounterSignerPublicKey
        {
            get
            {
                if (AsymmetricCounterAlgorithm == null) return null;
                try
                {
                    IAsymmetricPublicKey res = AsymmetricHelper.GetAlgorithm(AsymmetricCounterAlgorithm).DeserializePublicKey(
                        (CounterSignerPublicKeyData?.CloneArray() ?? throw new InvalidDataException("No counter signer public key data"))
                        );
                    try
                    {
                        return (ISignaturePublicKey)res;
                    }
                    catch
                    {
                        res.Dispose();
                        throw;
                    }
                }
                catch (CryptographicException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    throw CryptographicException.From(ex);
                }
            }
        }

        /// <summary>
        /// Signature purpose
        /// </summary>
        [CountLimit(1, ushort.MaxValue)]
        public string? Purpose { get; private set; }

        /// <summary>
        /// Create the hash to sign from this object
        /// </summary>
        /// <param name="forCounterSignature">For counter signature?</param>
        /// <returns>Hash to sign</returns>
        public byte[] CreateSignatureHash(bool forCounterSignature = false)
        {
            if (SignedData != null)
            {
                if (!forCounterSignature) return SignedData.Hash(new()
                {
                    HashAlgorithm = HashAlgorithm
                });
                if (forCounterSignature && CounterSignedData != null) return CounterSignedData.Hash(new()
                {
                    HashAlgorithm = HashAlgorithm
                });
            }
            byte[] signature = Signature;
            byte[]? counterSignature = CounterSignature;
            try
            {
                Nonce ??= RandomNumberGenerator.GetBytes(NONCE_LENGTH);
                if (Signature == null) Signed = DateTime.UtcNow;
                if (!forCounterSignature) Signature = Array.Empty<byte>();
                CounterSignature = null;
                CreateSignedData(forCounterSignature);
                return (forCounterSignature ? CounterSignedData : SignedData)!.Hash(new()
                {
                    HashAlgorithm = HashAlgorithm
                });
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
            finally
            {
                Signature = signature;
                CounterSignature = counterSignature;
            }
        }

        /// <summary>
        /// Validate signed data
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="throwOnError">Throw an exception on validation error?</param>
        /// <returns>If the signed data is valid</returns>
        public bool ValidateSignedData(byte[] data, bool throwOnError = true)
        {
            try
            {
                CryptoOptions options = HashHelper.GetDefaultOptions(new()
                {
                    HashAlgorithm = HashAlgorithm
                });
                using RentedArray<byte> buffer = new(HashHelper.GetAlgorithm(HashAlgorithm).HashLength);
                data.AsSpan().Hash(buffer.Span, options);
                bool res = buffer.Span.SlowCompare(SignedDataHash);
                if (!res && throwOnError) throw new InvalidDataException("Signed data hash mismatch");
                return res;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Validate signed data
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="throwOnError">Throw an exception on validation error?</param>
        /// <returns>If the signed data is valid</returns>
        public bool ValidateSignedData(Stream data, bool throwOnError = true)
        {
            try
            {
                CryptoOptions options = HashHelper.GetDefaultOptions(new()
                {
                    HashAlgorithm = HashAlgorithm
                });
                bool res = data.Hash(options).AsSpan().SlowCompare(SignedDataHash);
                if (!res && throwOnError) throw new InvalidDataException("Signed data hash mismatch");
                return res;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Validate signed data
        /// </summary>
        /// <param name="data">Raw data</param>
        /// <param name="throwOnError">Throw an exception on validation error?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the signed data is valid</returns>
        public async Task<bool> ValidateSignedDataAsync(Stream data, bool throwOnError = true, CancellationToken cancellationToken = default)
        {
            try
            {
                CryptoOptions options = HashHelper.GetDefaultOptions(new()
                {
                    HashAlgorithm = HashAlgorithm
                });
                byte[] hash = await data.HashAsync(options, cancellationToken).DynamicContext();
                bool res = hash.AsSpan().SlowCompare(SignedDataHash);
                if (!res && throwOnError) throw new InvalidDataException("Signed data hash mismatch");
                return res;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw await CryptographicException.FromAsync(ex);
            }
        }

        /// <summary>
        /// Clone this instance
        /// </summary>
        /// <returns>Clone</returns>
        public SignatureContainer Clone() => new()
        {
            SignedData = (byte[]?)SignedData?.Clone(),
            Signed = Signed,
            HashAlgorithm = HashAlgorithm,
            AsymmetricAlgorithm = AsymmetricAlgorithm,
            AsymmetricCounterAlgorithm = AsymmetricCounterAlgorithm,
            SignedDataHash = SignedDataHash.CloneArray(),
            Nonce = (byte[])(Nonce?.Clone() ?? throw new InvalidOperationException()),
            Signature = Signature.CloneArray(),
            Signer = Signer.CloneArray(),
            SignerPublicKeyData = SignerPublicKeyData.CloneArray(),
            CounterSignature = (byte[]?)CounterSignature?.Clone(),
            CounterSigner = (byte[]?)CounterSigner?.Clone(),
            CounterSignerPublicKeyData = (byte[]?)CounterSignerPublicKeyData?.Clone()
        };

        /// <inheritdoc/>
        object ICloneable.Clone() => Clone();

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            if (SignedData == null) throw new SerializerException("Missing signed data", new InvalidOperationException());
            stream.WriteBytes(SignedData)
                .WriteBytesNullable(CounterSignedData)
                .WriteBytes(Signature)
                .WriteBytesNullable(CounterSignature);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            if (SignedData == null) throw new SerializerException("Missing signed data", new InvalidOperationException());
            await stream.WriteBytesAsync(SignedData, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterSignedData, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Signature, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterSignature, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            SignedData = stream.ReadBytes(version, minLen: 1, maxLen: 262140).Value;
            CounterSignedData = stream.ReadBytesNullable(version, minLen: 1, maxLen: 262140)?.Value;
            DeserializeSignedData();
            Signature = stream.ReadBytes(version, minLen: 1, maxLen: ushort.MaxValue).Value;
            CounterSignature = stream.ReadBytesNullable(version, minLen: 1, maxLen: ushort.MaxValue)?.Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            SignedData = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: 262140, cancellationToken: cancellationToken).DynamicContext()).Value;
            CounterSignedData = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: 262140, cancellationToken: cancellationToken).DynamicContext())?.Value;
            DeserializeSignedData();
            Signature = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            CounterSignature = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
        }

        /// <summary>
        /// Create the signed data
        /// </summary>
        /// <param name="forCounterSignature">For counter signature?</param>
        private void CreateSignedData(bool forCounterSignature)
        {
            using MemoryStream ms = new();
            ms.WriteSerializerVersion()
                .WriteNumber(VERSION)
                .WriteBytes(Nonce)
                .WriteNumber(Signed.Ticks)
                .WriteString(HashAlgorithm)
                .WriteString(AsymmetricAlgorithm)
                .WriteStringNullable(AsymmetricCounterAlgorithm)
                .WriteBytes(SignedDataHash)
                .WriteBytes(Signature)
                .WriteBytes(Signer)
                .WriteBytes(SignerPublicKeyData)
                .WriteBytesNullable(CounterSigner)
                .WriteBytesNullable(CounterSignerPublicKeyData)
                .WriteStringNullable(Purpose);
            if (forCounterSignature)
            {
                CounterSignedData = ms.ToArray();
            }
            else
            {
                SignedData = ms.ToArray();
            }
        }

        /// <summary>
        /// Deserialize the signed data
        /// </summary>
        private void DeserializeSignedData()
        {
            using MemoryStream ms = new(CounterSignedData ?? SignedData ?? throw new InvalidOperationException());
            int ssv = ms.ReadSerializerVersion(),
                ov = ms.ReadNumber<int>(ssv);
            if (ov < 1 || ov > VERSION) throw new SerializerException($"Invalid signature container object version {ov}", new InvalidDataException());
            Nonce = ms.ReadBytes(ssv, minLen: 20, maxLen: NONCE_LENGTH).Value;
            Signed = new DateTime(ms.ReadNumber<long>(ssv));
            HashAlgorithm = ms.ReadString(ssv, minLen: 1, maxLen: byte.MaxValue);
            AsymmetricAlgorithm = ms.ReadString(ssv, minLen: 1, maxLen: byte.MaxValue);
            AsymmetricCounterAlgorithm = ms.ReadStringNullable(ssv, minLen: 1, maxLen: byte.MaxValue);
            SignedDataHash = ms.ReadBytes(ssv, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue).Value;
            Signature = ms.ReadBytes(ssv, minLen: 0, maxLen: ushort.MaxValue).Value;
            Signer = ms.ReadBytes(ssv, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue).Value;
            SignerPublicKeyData = ms.ReadBytes(ssv, minLen: 1, maxLen: ushort.MaxValue).Value;
            CounterSigner = ms.ReadBytesNullable(ssv, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue)?.Value;
            CounterSignerPublicKeyData = ms.ReadBytesNullable(ssv, minLen: 1, maxLen: ushort.MaxValue)?.Value;
            Purpose = ms.ReadStringNullable(ssv, minLen: 1, maxLen: ushort.MaxValue);
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="signature">Signature</param>
        public static implicit operator byte[](SignatureContainer signature) => signature.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator SignatureContainer(byte[] data) => data.ToObject<SignatureContainer>();
    }
}
