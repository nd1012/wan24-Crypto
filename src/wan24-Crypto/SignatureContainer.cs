using System.ComponentModel.DataAnnotations;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Signature container
    /// </summary>
    public sealed record class SignatureContainer : StreamSerializerRecordBase
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 2;
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
            SignerPublicKeyData = signer.PublicKey.Export();
            CounterSigner = counterSigner?.ID;
            CounterSignerPublicKeyData = counterSigner?.PublicKey.Export();
            Purpose = purpose;
        }

        /// <summary>
        /// Max. array length in serialized signature container data in bytes
        /// </summary>
        public static int MaxArrayLength { get; set; } = ushort.MaxValue << 2;

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
        [RuntimeCountLimit("wan24.Crypto.SignatureContainer.MaxArrayLength", min: 1)]
        public byte[] Signature { get; set; } = null!;

        /// <summary>
        /// Counter signature (signs all data including the signature)
        /// </summary>
        [RuntimeCountLimit("wan24.Crypto.SignatureContainer.MaxArrayLength", min: 1), RequiredIf(nameof(CounterSigner))]
        public byte[]? CounterSignature { get; set; }

        /// <summary>
        /// Signer
        /// </summary>
        [CountLimit(HashSha512Algorithm.HASH_LENGTH, byte.MaxValue)]
        public byte[] Signer { get; private set; } = null!;

        /// <summary>
        /// Counter signer
        /// </summary>
        [CountLimit(HashSha512Algorithm.HASH_LENGTH, byte.MaxValue), RequiredIf(nameof(CounterSignature))]
        public byte[]? CounterSigner { get; private set; }

        /// <summary>
        /// Signer public key data
        /// </summary>
        [RuntimeCountLimit("wan24.Crypto.AsymmetricKeyBase.MaxArrayLength", min: 1)]
        public byte[] SignerPublicKeyData { get; private set; } = null!;

        /// <summary>
        /// Counter signer public key data
        /// </summary>
        [RuntimeCountLimit("wan24.Crypto.AsymmetricKeyBase.MaxArrayLength", min: 1), RequiredIf(nameof(CounterSigner))]
        public byte[]? CounterSignerPublicKeyData { get; private set; }

        /// <summary>
        /// Signer public key (don't forget to dispose!)
        /// </summary>
        [NoValidation]
        public ISignaturePublicKey SignerPublicKey
        {
            get
            {
                try
                {
                    IAsymmetricPublicKey res;
                    if (SerializedObjectVersion.HasValue)
                    {
                        res = SerializedObjectVersion.Value switch// Object version switch
                        {
                            1 => AsymmetricHelper.GetAlgorithm(AsymmetricAlgorithm).DeserializePublicKey(SignerPublicKeyData),
                            _ => AsymmetricKeyBase.Import(SignerPublicKeyData) as IAsymmetricPublicKey ?? throw new InvalidDataException("Failed to import signer public key data"),
                        };
                    }
                    else
                    {
                        res = AsymmetricKeyBase.Import(SignerPublicKeyData) as IAsymmetricPublicKey ?? throw new InvalidDataException("Failed to import signer public key data");
                    }
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
        [NoValidation]
        public ISignaturePublicKey? CounterSignerPublicKey
        {
            get
            {
                if (AsymmetricCounterAlgorithm is null) return null;
                try
                {
                    IAsymmetricPublicKey res;
                    if (SerializedObjectVersion.HasValue)
                    {
                        res = SerializedObjectVersion.Value switch// Object version switch
                        {
                            1 => AsymmetricHelper.GetAlgorithm(AsymmetricCounterAlgorithm).DeserializePublicKey(CounterSignerPublicKeyData
                                                                ?? throw new InvalidDataException("No counter signer public key data")),
                            _ => AsymmetricKeyBase.Import(CounterSignerPublicKeyData ?? throw new InvalidDataException("No counter signer public key data")) as IAsymmetricPublicKey
                                                                ?? throw new InvalidDataException("Failed to import counter signer public key data"),
                        };
                    }
                    else
                    {
                        res = AsymmetricKeyBase.Import(SignerPublicKeyData) as IAsymmetricPublicKey ?? throw new InvalidDataException("Failed to import signer public key data");
                    }
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
            if (SignedData is not null)
            {
                if (!forCounterSignature) return SignedData.Hash(new()
                {
                    HashAlgorithm = HashAlgorithm
                });
                if (forCounterSignature && CounterSignedData is not null) return CounterSignedData.Hash(new()
                {
                    HashAlgorithm = HashAlgorithm
                });
            }
            byte[] signature = Signature;
            byte[]? counterSignature = CounterSignature;
            try
            {
                Nonce ??= RND.GetBytes(NONCE_LENGTH);
                if (Signature is null) Signed = DateTime.UtcNow;
                if (!forCounterSignature) Signature = [];
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
                using RentedArrayRefStruct<byte> buffer = new(HashHelper.GetAlgorithm(HashAlgorithm).HashLength);
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
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public SignatureContainer GetCopy() => new()
        {
            SignedData = SignedData?.CloneArray(),
            Signed = Signed,
            HashAlgorithm = HashAlgorithm,
            AsymmetricAlgorithm = AsymmetricAlgorithm,
            AsymmetricCounterAlgorithm = AsymmetricCounterAlgorithm,
            SignedDataHash = SignedDataHash.CloneArray(),
            Nonce = Nonce?.CloneArray() ?? throw new InvalidOperationException(),
            Signature = Signature.CloneArray(),
            Signer = Signer.CloneArray(),
            SignerPublicKeyData = SignerPublicKeyData.CloneArray(),
            CounterSignature = CounterSignature?.CloneArray(),
            CounterSigner = CounterSigner?.CloneArray(),
            CounterSignerPublicKeyData = CounterSignerPublicKeyData?.CloneArray()
        };

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            if (SignedData is null) throw new SerializerException("Missing signed data", new InvalidOperationException());
            stream.WriteBytes(SignedData)
                .WriteBytesNullable(CounterSignedData)
                .WriteBytes(Signature)
                .WriteBytesNullable(CounterSignature);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            if (SignedData is null) throw new SerializerException("Missing signed data", new InvalidOperationException());
            await stream.WriteBytesAsync(SignedData, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterSignedData, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Signature, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterSignature, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            SignedData = stream.ReadBytes(version, minLen: 1, maxLen: MaxArrayLength << 1).Value;
            CounterSignedData = stream.ReadBytesNullable(version, minLen: 1, maxLen: MaxArrayLength << 1)?.Value;
            DeserializeSignedData();
            Signature = stream.ReadBytes(version, minLen: 1, maxLen: MaxArrayLength).Value;
            CounterSignature = stream.ReadBytesNullable(version, minLen: 1, maxLen: MaxArrayLength)?.Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            SignedData = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: MaxArrayLength << 1, cancellationToken: cancellationToken).DynamicContext()).Value;
            CounterSignedData = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: MaxArrayLength << 1, cancellationToken: cancellationToken).DynamicContext())?.Value;
            DeserializeSignedData();
            Signature = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: MaxArrayLength, cancellationToken: cancellationToken).DynamicContext()).Value;
            CounterSignature = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: MaxArrayLength, cancellationToken: cancellationToken).DynamicContext())?.Value;
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
            Signature = ms.ReadBytes(ssv, minLen: 0, maxLen: MaxArrayLength).Value;
            Signer = ms.ReadBytes(ssv, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue).Value;
            SignerPublicKeyData = ms.ReadBytes(ssv, minLen: 1, maxLen: AsymmetricKeyBase.MaxArrayLength).Value;
            CounterSigner = ms.ReadBytesNullable(ssv, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue)?.Value;
            CounterSignerPublicKeyData = ms.ReadBytesNullable(ssv, minLen: 1, maxLen: AsymmetricKeyBase.MaxArrayLength)?.Value;
            Purpose = ms.ReadStringNullable(ssv, minLen: 1, maxLen: ushort.MaxValue);
            // Apply RNG seeding
            if ((RND.AutoRngSeeding & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                RND.AddSeed(Nonce);
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
