using System.Security.Cryptography;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Signature container
    /// </summary>
    public sealed class SignatureContainer : StreamSerializerBase
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
            SignerPublicKeyData = (byte[])signer.PublicKey.KeyData.Array.Clone();
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
        public string HashAlgorithm { get; private set; } = null!;

        /// <summary>
        /// Asymmetric algorithm name
        /// </summary>
        public string AsymmetricAlgorithm { get; private set; } = null!;

        /// <summary>
        /// Asymmetric counter algorithm name
        /// </summary>
        public string? AsymmetricCounterAlgorithm { get; private set; }

        /// <summary>
        /// Signed data hash
        /// </summary>
        public byte[] SignedDataHash { get; private set; } = null!;

        /// <summary>
        /// Nonce
        /// </summary>
        public byte[]? Nonce { get; private set; } = null!;

        /// <summary>
        /// Signature (signs all data except the counter signature)
        /// </summary>
        public byte[] Signature { get; set; } = null!;

        /// <summary>
        /// Counter signature (signs all data including the signature)
        /// </summary>
        public byte[]? CounterSignature { get; set; }

        /// <summary>
        /// Signer
        /// </summary>
        public byte[] Signer { get; private set; } = null!;

        /// <summary>
        /// Counter signer
        /// </summary>
        public byte[]? CounterSigner { get; private set; }

        /// <summary>
        /// Signer public key data
        /// </summary>
        public byte[] SignerPublicKeyData { get; private set; } = null!;

        /// <summary>
        /// Counter signer public key data
        /// </summary>
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
                    IAsymmetricPublicKey res = AsymmetricHelper.GetAlgorithm(AsymmetricAlgorithm).DeserializePublicKey((byte[])SignerPublicKeyData.Clone());
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
                        (byte[])(CounterSignerPublicKeyData?.Clone() ?? throw new InvalidDataException("No counter signer public key data"))
                        );
                    try
                    {
                        return (ISignaturePublicKey)res;
                    }
                    catch
                    {
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
        public string? Purpose { get; private set; }

        /// <summary>
        /// Create the hash to sign from this object
        /// </summary>
        /// <param name="forCounterSignature">For counter signature?</param>
        /// <returns>Hash to sign</returns>
        public byte[] CreateSignatureHash(bool forCounterSignature = false)
        {
            byte[] signature = Signature;
            byte[]? counterSignature = CounterSignature;
            try
            {
                Nonce ??= RandomNumberGenerator.GetBytes(NONCE_LENGTH);
                if (Signature == null) Signed = DateTime.UtcNow;
                if (!forCounterSignature) Signature = Array.Empty<byte>();
                CounterSignature = null;
                using MemoryStream ms = new();
                Serialize(ms);
                return ms.ToArray().Hash(new()
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
            using MemoryStream ms = new(data);
            return ValidateSignedData(ms, throwOnError);
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
                byte[] hash = data.Hash(options);
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
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteBytes(Nonce)
                .WriteNumber(Signed.Ticks)
                .WriteString(HashAlgorithm)
                .WriteString(AsymmetricAlgorithm)
                .WriteStringNullable(AsymmetricCounterAlgorithm)
                .WriteBytes(SignedDataHash)
                .WriteBytes(Signature)
                .WriteBytesNullable(CounterSignature)
                .WriteBytes(Signer)
                .WriteBytesNullable(SignerPublicKeyData)
                .WriteBytesNullable(CounterSigner)
                .WriteBytesNullable(CounterSignerPublicKeyData)
                .WriteStringNullable(Purpose);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteBytesAsync(Nonce, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(Signed.Ticks, cancellationToken).DynamicContext();
            await stream.WriteStringAsync(HashAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteStringAsync(AsymmetricAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(AsymmetricCounterAlgorithm, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(SignedDataHash, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Signature, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterSignature, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Signer, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(SignerPublicKeyData, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterSigner, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterSignerPublicKeyData, cancellationToken).DynamicContext();
            await stream.WriteStringNullableAsync(Purpose, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Nonce = stream.ReadBytes(version, minLen: 20, maxLen: NONCE_LENGTH).Value;
            Signed = new DateTime(stream.ReadNumber<long>(version));
            HashAlgorithm = stream.ReadString(version, minLen: 1, maxLen: byte.MaxValue);
            AsymmetricAlgorithm = stream.ReadString(version, minLen: 1, maxLen: byte.MaxValue);
            AsymmetricCounterAlgorithm = stream.ReadStringNullable(version, minLen: 1, maxLen: byte.MaxValue);
            SignedDataHash = stream.ReadBytes(version, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue).Value;
            Signature = stream.ReadBytes(version, minLen: 1, maxLen: ushort.MaxValue).Value;
            CounterSignature = stream.ReadBytesNullable(version, minLen: 1, maxLen: ushort.MaxValue)?.Value;
            Signer = stream.ReadBytes(version, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue).Value;
            SignerPublicKeyData = stream.ReadBytes(version, minLen: 1, maxLen: ushort.MaxValue).Value;
            CounterSigner = stream.ReadBytes(version, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue).Value;
            CounterSignerPublicKeyData = stream.ReadBytes(version, minLen: 1, maxLen: ushort.MaxValue).Value;
            Purpose = stream.ReadStringNullable(version, minLen: 1, maxLen: ushort.MaxValue);
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Nonce = (await stream.ReadBytesAsync(version, minLen: 20, maxLen: NONCE_LENGTH, cancellationToken: cancellationToken).DynamicContext()).Value;
            Signed = new DateTime(await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext());
            HashAlgorithm = await stream.ReadStringAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            AsymmetricAlgorithm = await stream.ReadStringAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            AsymmetricCounterAlgorithm = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            SignedDataHash = (await stream.ReadBytesAsync(version, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            Signature = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            CounterSignature = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
            Signer = (await stream.ReadBytesAsync(version, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            SignerPublicKeyData = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken)).Value;
            CounterSigner = (await stream.ReadBytesAsync(version, minLen: HashMd5Algorithm.HASH_LENGTH, maxLen: byte.MaxValue, cancellationToken: cancellationToken)).Value;
            CounterSignerPublicKeyData = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken)).Value;
            Purpose = await stream.ReadStringNullableAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public static implicit operator byte[](SignatureContainer privateKey) => privateKey.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator SignatureContainer(byte[] data) => data.ToObject<SignatureContainer>();
    }
}
