using System.Security;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Signed asymmetric public key
    /// </summary>
    public sealed class AsymmetricSignedPublicKey : DisposableBase, IStreamSerializerVersion
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Serialized object version
        /// </summary>
        private int? _SerializedObjectVersion = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSignedPublicKey() : base() { }

        /// <summary>
        /// Root public key trust validation (returns <see langword="true"/>, if the given root public key ID is trusted)
        /// </summary>
        public static RootTrust_Delegate RootTrust { get; set; } = (id) => true;

        /// <summary>
        /// Signed public key store (returns <see langword="null"/>, if the signed public key with the given ID wasn't found; do not dispose the returned key!)
        /// </summary>
        public static SignedPublicKeyStore_Delegate SignedPublicKeyStore { get; set; } = (id) => null;

        /// <summary>
        /// Signed public key revocation validation (returns <see langword="false"/>, if the public key with the given ID wasn't revoked)
        /// </summary>
        public static SignedPublicKeyRevocation_Delegate SignedPublicKeyRevocation { get; set; } = (id) => false;

        /// <summary>
        /// Maximum time difference
        /// </summary>
        public static TimeSpan? MaximumTimeDifference { get; set; }

        /// <summary>
        /// Signed public key
        /// </summary>
        public IAsymmetricPublicKey PublicKey { get; set; } = null!;

        /// <summary>
        /// Created time (UTC)
        /// </summary>
        public DateTime Created { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Expires time (UTC)
        /// </summary>
        public DateTime Expires { get; set; } = DateTime.UtcNow + TimeSpan.FromDays(365);

        /// <summary>
        /// Attributes
        /// </summary>
        [CountLimit(byte.MaxValue)]
        [ItemStringLength(byte.MaxValue, ItemValidationTargets.Key)]
        [ItemStringLength(byte.MaxValue)]
        public Dictionary<string, string> Attributes { get; private set; } = new();

        /// <summary>
        /// Signature
        /// </summary>
        public SignatureContainer Signature { get; set; } = null!;

        /// <summary>
        /// Signed signer public key (if not self signed)
        /// </summary>
        public AsymmetricSignedPublicKey? Signer { get; set; }

        /// <summary>
        /// Counter signed signer public key
        /// </summary>
        public AsymmetricSignedPublicKey? CounterSigner { get; set; }

        /// <inheritdoc/>
        int? IStreamSerializerVersion.ObjectVersion => VERSION;

        /// <inheritdoc/>
        int? IStreamSerializerVersion.SerializedObjectVersion => _SerializedObjectVersion;

        /// <summary>
        /// Sign the key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="publicKey">Signed public key of the signer</param>
        /// <param name="counterPrivateKey">Counter private key</param>
        /// <param name="counterPublicKey">Signed public key of the counter signer</param>
        /// <param name="purpose">Purpose</param>
        /// <param name="options">Options</param>
        public void Sign(
            ISignaturePrivateKey privateKey, 
            AsymmetricSignedPublicKey? publicKey = null, 
            ISignaturePrivateKey? counterPrivateKey = null,
            AsymmetricSignedPublicKey? counterPublicKey = null,
            string? purpose = null,
            CryptoOptions? options = null
            )
        {
            try
            {
                if (!privateKey.ID.SequenceEqual(PublicKey.ID)) Signer = publicKey;
                CounterSigner = counterPublicKey;
                options = AsymmetricHelper.GetDefaultSignatureOptions(options);
                options.CounterPrivateKey = counterPrivateKey;
                Signature = privateKey.SignData(GetSignedData(), purpose, options);
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
        /// Validate the signature
        /// </summary>
        /// <param name="deep">Deep validation until the self signed root</param>
        /// <param name="ignoreTime">Ignore the time?</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <returns>If the signature is valid</returns>
        public bool Validate(bool deep = true, bool ignoreTime = false, bool throwOnError = true)
        {
            try
            {
                // Validate the times
                if (!ignoreTime)
                {
                    DateTime now = DateTime.UtcNow;
                    if (Created > Expires)
                    {
                        if (throwOnError) throw new TimeoutException("Created after expired");
                        return false;
                    }
                    if (now < (MaximumTimeDifference == null ? Created : Created - MaximumTimeDifference))
                    {
                        if (throwOnError) throw new TimeoutException("Created in the future");
                        return false;
                    }
                    if (now > (MaximumTimeDifference == null ? Expires : Expires + MaximumTimeDifference))
                    {
                        if (throwOnError) throw new TimeoutException("Expired");
                        return false;
                    }
                    if (Created > Signature.Signed || Expires < Signature.Signed)
                    {
                        if (throwOnError) throw new TimeoutException("Invalid signature time");
                        return false;
                    }
                }
                // Validate the signature
                if (!Signature.SignerPublicKey.ValidateSignature(Signature, GetSignedData(), throwOnError)) return false;
                if (Signature.CounterSigner != null && !HybridAlgorithmHelper.ValidateCounterSignature(Signature))
                {
                    if (throwOnError) throw new InvalidDataException("Counter signature validation failed");
                    return false;
                }
                // Validate the signer
                if (Signer != null && !Signer.PublicKey.ID.SequenceEqual(Signature.Signer))
                {
                    if (throwOnError) throw new InvalidDataException("Signer mismatch");
                    return false;
                }
                // Validate the counter signer
                if (CounterSigner != null && CounterSigner.PublicKey.ID.SequenceEqual(Signature.CounterSigner!))
                {
                    if (throwOnError) throw new InvalidDataException("Counter signer mismatch");
                    return false;
                }
                // Validate if not revoked
                if (SignedPublicKeyRevocation(PublicKey.ID))
                {
                    if (throwOnError) throw new SecurityException("Key was revoked");
                    return false;
                }
                // Deep validation to the self signed root public keys
                if (deep)
                {
                    AsymmetricSignedPublicKey? signer = Signer;
                    if (Signature.Signer.SequenceEqual(PublicKey.ID))
                    {
                        // Self signed
                        if (!RootTrust(PublicKey.ID))
                        {
                            if (throwOnError) throw new SecurityException("Untrusted root signer");
                            return false;
                        }
                    }
                    else if (signer == null)
                    {
                        // Unknown signer
                        signer = SignedPublicKeyStore(Signature.Signer);
                        if (signer == null)
                        {
                            if (throwOnError) throw new InvalidDataException("Missing signed signer public key");
                            return false;
                        }
                    }
                    // Validate the signed signer public key
                    if (signer != null && !signer.Validate(ignoreTime: ignoreTime, throwOnError: throwOnError)) return false;
                    // Validate the counter signer
                    if (Signature.CounterSigner != null)
                    {
                        signer = CounterSigner;
                        if (signer == null)
                        {
                            // Unknown counter signer
                            signer = SignedPublicKeyStore(Signature.CounterSigner);
                            if (signer == null)
                            {
                                if (throwOnError) throw new InvalidDataException("Missing signed counter signer public key");
                                return false;
                            }
                        }
                        // Validate the signed counter signer public key
                        if (signer != null && !signer.Validate(ignoreTime: ignoreTime, throwOnError: throwOnError)) return false;
                    }
                }
                return true;
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
        /// Get the signed data
        /// </summary>
        /// <returns>Signed data</returns>
        public byte[] GetSignedData()
        {
            SignatureContainer signature = Signature;
            try
            {
                this.ValidateObject();
                using MemoryStream ms = new();
                ms.WriteAny(PublicKey);
                ms.WriteNumber(Created.Ticks);
                ms.WriteNumber(Expires.Ticks);
                ms.WriteDict(Attributes);
                return ms.ToArray();
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
            }
        }

        /// <inheritdoc/>
        public void Serialize(Stream stream)
        {
            stream.WriteNumber(VERSION);
            stream.Write(GetSignedData());
            stream.WriteSerialized(Signature)
                .WriteAnyNullable(Signer)
                .WriteAnyNullable(CounterSigner);
        }

        /// <inheritdoc/>
        public async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteNumberAsync(VERSION, cancellationToken).DynamicContext();
            await stream.WriteAsync(GetSignedData(), cancellationToken).DynamicContext();
            await stream.WriteSerializedAsync(Signature, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(Signer, cancellationToken).DynamicContext();
            await stream.WriteAnyNullableAsync(CounterSigner, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        public void Deserialize(Stream stream, int version)
        {
            _SerializedObjectVersion = StreamSerializerAdapter.ReadSerializedObjectVersion(stream, version, VERSION);
            PublicKey = (IAsymmetricPublicKey)stream.ReadAny(version);
            Created = new DateTime(stream.ReadNumber<long>(version));
            Expires = new DateTime(stream.ReadNumber<long>(version));
            Attributes = stream.ReadDict<string, string>(maxLen: byte.MaxValue);
            Signature = stream.ReadSerialized<SignatureContainer>(version);
            Signer = stream.ReadAnyNullable(version) as AsymmetricSignedPublicKey;
            CounterSigner = stream.ReadAnyNullable(version) as AsymmetricSignedPublicKey;
        }

        /// <inheritdoc/>
        public async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            _SerializedObjectVersion = await StreamSerializerAdapter.ReadSerializedObjectVersionAsync(stream, version, VERSION, cancellationToken).DynamicContext();
            PublicKey = (IAsymmetricPublicKey)await stream.ReadAnyAsync(version, cancellationToken).DynamicContext();
            Created = new DateTime(await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext());
            Expires = new DateTime(await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext());
            Attributes = await stream.ReadDictAsync<string, string>(maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
            Signature = await stream.ReadSerializedAsync<SignatureContainer>(version, cancellationToken).DynamicContext();
            Signer = await stream.ReadAnyNullableAsync(version, cancellationToken).DynamicContext() as AsymmetricSignedPublicKey;
            CounterSigner = await stream.ReadAnyNullableAsync(version, cancellationToken).DynamicContext() as AsymmetricSignedPublicKey;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => PublicKey.Dispose();

        /// <summary>
        /// Delegate for root key trust validation
        /// </summary>
        /// <param name="id">Root public key ID</param>
        /// <returns>Is trusted?</returns>
        public delegate bool RootTrust_Delegate(byte[] id);

        /// <summary>
        /// Delegate for a public key store
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        /// <returns>Public key</returns>
        public delegate AsymmetricSignedPublicKey? SignedPublicKeyStore_Delegate(byte[] id);

        /// <summary>
        /// Delegate for signed public key revocation validation
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        /// <returns>If the key was revoked</returns>
        public delegate bool SignedPublicKeyRevocation_Delegate(byte[] id);
    }
}
