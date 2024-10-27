using System.Security;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Signed asymmetric public key
    /// </summary>
    public sealed record class AsymmetricSignedPublicKey : DisposableStreamSerializerRecordBase
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
        /// Key type
        /// </summary>
        private AsymmetricSignedPublicKeyTypes? _Type = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public AsymmetricSignedPublicKey() : base(VERSION) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKey">Public key (will be copied)</param>
        /// <param name="attributes">Attributes</param>
        public AsymmetricSignedPublicKey(in IAsymmetricPublicKey publicKey, in Dictionary<string, string>? attributes = null) : this()
        {
            PublicKey = publicKey.GetCopy();
            if (attributes is not null) Attributes.AddRange(attributes);
        }

        /// <summary>
        /// Root public key trust validation (returns <see langword="true"/>, if the given root public key ID is trusted)
        /// </summary>
        public static RootTrust_Delegate RootTrust { get; set; } = (id) => true;

        /// <summary>
        /// Root public key trust validation (returns <see langword="true"/>, if the given root public key ID is trusted)
        /// </summary>
        public static RootTrustAsync_Delegate RootTrustAsync { get; set; } = (id, ct) => Task.FromResult(true);

        /// <summary>
        /// Signed public key store (returns <see langword="null"/>, if the signed public key with the given ID wasn't found; do not dispose the returned key!)
        /// </summary>
        public static SignedPublicKeyStore_Delegate SignedPublicKeyStore { get; set; } = (id) => null;

        /// <summary>
        /// Signed public key store (returns <see langword="null"/>, if the signed public key with the given ID wasn't found; do not dispose the returned key!)
        /// </summary>
        public static SignedPublicKeyStoreAsync_Delegate SignedPublicKeyStoreAsync { get; set; } = (id, ct) => Task.FromResult((AsymmetricSignedPublicKey?)null);

        /// <summary>
        /// Signed public key revocation validation (returns <see langword="false"/>, if the public key with the given ID wasn't revoked)
        /// </summary>
        public static SignedPublicKeyRevocation_Delegate SignedPublicKeyRevocation { get; set; } = (id) => false;

        /// <summary>
        /// Signed public key revocation validation (returns <see langword="false"/>, if the public key with the given ID wasn't revoked)
        /// </summary>
        public static SignedPublicKeyRevocationAsync_Delegate SignedPublicKeyRevocationAsync { get; set; } = (id, ct) => Task.FromResult(false);

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
        public Dictionary<string, string> Attributes { get; private set; } = [];

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

        /// <summary>
        /// Key type
        /// </summary>
        public AsymmetricSignedPublicKeyTypes Type
        {
            get
            {
                EnsureUndisposed();
                if (_Type.HasValue) return _Type.Value;
                if (
                    (PublicKey.Algorithm.CanSign || Attributes.ContainsKey(SignedAttributes.SIGNATURE_PUBLIC_KEY_IDENTIFIER)) &&
                    (!Attributes.TryGetValue(SignedAttributes.PKI_SIGNATURE, out string? pkiSig) || (bool.TryParse(pkiSig, out bool pkiSigFlag) && pkiSigFlag))
                    )
                {
                    _Type = Signer is null ? AsymmetricSignedPublicKeyTypes.Root : AsymmetricSignedPublicKeyTypes.Intermediate;
                }
                else
                {
                    _Type = AsymmetricSignedPublicKeyTypes.End;
                }
                return _Type.Value;
            }
        }

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
            in ISignaturePrivateKey privateKey,
            in AsymmetricSignedPublicKey? publicKey = null,
            in ISignaturePrivateKey? counterPrivateKey = null,
            in AsymmetricSignedPublicKey? counterPublicKey = null,
            in string? purpose = null,
            CryptoOptions? options = null
            )
        {
            try
            {
                EnsureUndisposed();
                if (publicKey is not null && !publicKey.PublicKey.ID.SequenceEqual(privateKey.ID)) throw new ArgumentException("Public key ID mismatch", nameof(publicKey));
                if (counterPrivateKey is not null && counterPublicKey is not null && !counterPublicKey.PublicKey.ID.SequenceEqual(counterPrivateKey.ID))
                    throw new ArgumentException("Public key ID mismatch", nameof(counterPublicKey));
                if ((publicKey?.Attributes.TryGetValue(SignedAttributes.PKI_SIGNATURE, out string? pkiSig) ?? false) && (!bool.TryParse(pkiSig, out bool pkiSigFlag) || !pkiSigFlag))
                    throw new UnauthorizedAccessException("Key isn't permitted to sign a PKI sub-key");
                if ((counterPublicKey?.Attributes.TryGetValue(SignedAttributes.PKI_SIGNATURE, out string? pkiSigC) ?? false) && (!bool.TryParse(pkiSigC, out bool pkiSigCFlag) || !pkiSigCFlag))
                    throw new UnauthorizedAccessException("Counter key isn't permitted to sign a PKI sub-key");
                if (!privateKey.ID.SequenceEqual(PublicKey.ID) && (counterPrivateKey is null || !counterPrivateKey.ID.SequenceEqual(PublicKey.ID)))
                {
                    Signer = publicKey;
                    CounterSigner = counterPublicKey;
                }
                options = AsymmetricHelper.GetDefaultSignatureOptions(options)
                    .WithSignatureKey(privateKey, counterPrivateKey);
                Signature = privateKey.SignData(CreateSignedData(), purpose, options);
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
        /// <param name="options">Attribute validation options</param>
        /// <param name="requirePkiSignaturePermission">Require PKI signature permission attribute? (<see langword="null"/> for automatic)</param>
        /// <returns>If the signature is valid</returns>
        public bool Validate(
            in bool deep = true, 
            in bool ignoreTime = false, 
            in bool throwOnError = true, 
            SignedAttributes.ValidationOptions? options = null,
            in bool? requirePkiSignaturePermission = null
            )
        {
            try
            {
                EnsureUndisposed();
                // Validate the times
                if (!ignoreTime)
                {
                    DateTime now = DateTime.UtcNow;
                    if (Created > Expires)
                    {
                        if (throwOnError) throw new TimeoutException("Created after expired");
                        return false;
                    }
                    if (now < (MaximumTimeDifference is null ? Created : Created - MaximumTimeDifference))
                    {
                        if (throwOnError) throw new TimeoutException("Created in the future");
                        return false;
                    }
                    if (now > (MaximumTimeDifference is null ? Expires : Expires + MaximumTimeDifference))
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
                using (ISignaturePublicKey signerKey = Signature.SignerPublicKey)
                    if (!signerKey.ValidateSignature(Signature, CreateSignedData(), throwOnError)) return false;
                if (Signature.CounterSigner is not null && !HybridAlgorithmHelper.ValidateCounterSignature(Signature))
                {
                    if (throwOnError) throw new InvalidDataException("Counter signature validation failed");
                    return false;
                }
                // Validate the attributes
                options ??= new();
                SignedAttributes.Validate(PublicKey.ID, Attributes, throwOnError, options);
                options.RequirePkiSignaturePermission = requirePkiSignaturePermission ?? false;
                // Validate the signer
                if (Signer is not null && !Signer.PublicKey.ID.SequenceEqual(Signature.Signer))
                {
                    if (throwOnError) throw new InvalidDataException("Signer mismatch");
                    return false;
                }
                // Validate the counter signer
                if (CounterSigner is not null && !CounterSigner.PublicKey.ID.SequenceEqual(Signature.CounterSigner!))
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
                    else if (signer is null)
                    {
                        // Unknown signer
                        signer = SignedPublicKeyStore(Signature.Signer);
                        if (signer is null)
                        {
                            if (throwOnError) throw new InvalidDataException("Missing signed signer public key");
                            return false;
                        }
                    }
                    // Validate the signed signer public key
                    if (
                        signer is not null &&
                        !signer.PublicKey.ID.SequenceEqual(PublicKey.ID) &&
                        !signer.Validate(deep: true, ignoreTime, throwOnError, options)
                        )
                        return false;
                    // Validate the counter signer
                    if (
                        Signature.CounterSigner is not null &&
                        CounterSigner is not null &&
                        !CounterSigner.Validate(deep: true, ignoreTime, throwOnError, options)
                        )
                        return false;
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
        /// Validate the signature
        /// </summary>
        /// <param name="deep">Deep validation until the self signed root</param>
        /// <param name="ignoreTime">Ignore the time?</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <param name="options">Attribute validation options</param>
        /// <param name="requirePkiSignaturePermission">Require PKI signature permission attribute? (<see langword="null"/> for automatic)</param>
        /// <param name="services">Service provider to use, if <c>httpClient</c> wasn't given for online key validation</param>
        /// <param name="httpClient">http client to use for online key validation (won't be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the signature is valid</returns>
        public async Task<bool> ValidateAsync(
            bool deep = true, 
            bool ignoreTime = false, 
            bool throwOnError = true,
            SignedAttributes.ValidationOptions? options = null,
            bool? requirePkiSignaturePermission = null,
            IServiceProvider? services = null,
            HttpClient? httpClient = null,
            CancellationToken cancellationToken = default
            )
        {
            await Task.Yield();
            try
            {
                EnsureUndisposed();
                // Validate the times
                if (!ignoreTime)
                {
                    DateTime now = DateTime.UtcNow;
                    if (Created > Expires)
                    {
                        if (throwOnError) throw new TimeoutException("Created after expired");
                        return false;
                    }
                    if (now < (MaximumTimeDifference is null ? Created : Created - MaximumTimeDifference))
                    {
                        if (throwOnError) throw new TimeoutException("Created in the future");
                        return false;
                    }
                    if (now > (MaximumTimeDifference is null ? Expires : Expires + MaximumTimeDifference))
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
                using (ISignaturePublicKey signerKey = Signature.SignerPublicKey)
                    if (!signerKey.ValidateSignature(Signature, CreateSignedData(), throwOnError)) return false;
                if (Signature.CounterSigner is not null && !HybridAlgorithmHelper.ValidateCounterSignature(Signature))
                {
                    if (throwOnError) throw new InvalidDataException("Counter signature validation failed");
                    return false;
                }
                // Validate the attributes
                options ??= new();
                await SignedAttributes.ValidateAsync(
                    PublicKey.ID, 
                    Attributes, 
                    throwOnError, 
                    options, 
                    keyStore: null, 
                    ignoreTime ? null : DateTime.UtcNow, 
                    services, 
                    httpClient, 
                    cancellationToken
                    ).DynamicContext();
                options.RequirePkiSignaturePermission = requirePkiSignaturePermission ?? false;
                // Validate the signer
                if (Signer is not null && !Signer.PublicKey.ID.SequenceEqual(Signature.Signer))
                {
                    if (throwOnError) throw new InvalidDataException("Signer mismatch");
                    return false;
                }
                // Validate the counter signer
                if (CounterSigner is not null && !CounterSigner.PublicKey.ID.SequenceEqual(Signature.CounterSigner!))
                {
                    if (throwOnError) throw new InvalidDataException("Counter signer mismatch");
                    return false;
                }
                // Validate if not revoked
                if (await SignedPublicKeyRevocationAsync(PublicKey.ID, cancellationToken).DynamicContext())
                {
                    if (throwOnError) throw new SecurityException($"Key was revoked {Convert.ToHexString(PublicKey.ID)}");
                    return false;
                }
                // Deep validation to the self signed root public keys
                if (deep)
                {
                    AsymmetricSignedPublicKey? signer = Signer;
                    if (Signature.Signer.SequenceEqual(PublicKey.ID))
                    {
                        // Self signed
                        if (!await RootTrustAsync(PublicKey.ID, cancellationToken).DynamicContext())
                        {
                            if (throwOnError) throw new SecurityException("Untrusted root signer");
                            return false;
                        }
                    }
                    else if (signer is null)
                    {
                        // Unknown signer
                        signer = await SignedPublicKeyStoreAsync(Signature.Signer, cancellationToken).DynamicContext();
                        if (signer is null)
                        {
                            if (throwOnError) throw new InvalidDataException("Missing signed signer public key");
                            return false;
                        }
                    }
                    // Validate the signed signer public key
                    if (
                        signer is not null &&
                        !signer.PublicKey.ID.SequenceEqual(PublicKey.ID) &&
                        !await signer.ValidateAsync(deep: true, ignoreTime, throwOnError, options, cancellationToken: cancellationToken).DynamicContext()
                        )
                        return false;
                    // Validate the counter signer
                    if (
                        Signature.CounterSigner is not null &&
                        CounterSigner is not null &&
                        !await CounterSigner.ValidateAsync(deep: true, ignoreTime, throwOnError, options, cancellationToken: cancellationToken).DynamicContext()
                        )
                        return false;
                }
                return true;
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
                    .WriteNumber(Created.Ticks)
                    .WriteNumber(Expires.Ticks)
                    .WriteDict(Attributes)
                    .WriteSerializedNullable(Signer)
                    .WriteSerializedNullable(CounterSigner);
                SignedData = ms.ToArray();
                return SignedData;
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
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public AsymmetricSignedPublicKey GetCopy() => IfUndisposed(() => new AsymmetricSignedPublicKey()
        {
            SignedData = SignedData?.CloneArray(),
            PublicKey = PublicKey.GetCopy(),
            Created = Created,
            Expires = Expires,
            Attributes = new(Attributes),
            Signature = Signature.GetCopy(),
            Signer = Signer?.GetCopy(),
            CounterSigner = CounterSigner?.GetCopy()
        });

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            CreateSignedData();
            stream.WriteBytes(SignedData!)
                .WriteSerialized(Signature);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            CreateSignedData();
            await stream.WriteBytesAsync(SignedData, cancellationToken).DynamicContext();
            await stream.WriteSerializedAsync(Signature, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            SignedData = stream.ReadArray<byte>(version, minLen: 1, maxLen: SignatureContainer.MaxArrayLength << 1);
            DeserializeSignedData();
            Signature = stream.ReadSerialized<SignatureContainer>(version);
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            SignedData = await stream.ReadArrayAsync<byte>(version, minLen: 1, maxLen: SignatureContainer.MaxArrayLength << 1, cancellationToken: cancellationToken).DynamicContext();
            DeserializeSignedData();
            Signature = await stream.ReadSerializedAsync<SignatureContainer>(version, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => PublicKey.Dispose();

        /// <summary>
        /// Deserialize the signed data
        /// </summary>
        private void DeserializeSignedData()
        {
            EnsureUndisposed();
            if (SignedData is null) throw new InvalidOperationException();
            using MemoryStream ms = new(SignedData);
            int ssv = ms.ReadSerializerVersion(),
                ov = ms.ReadNumber<int>(ssv);
            if (ov < 1 || ov > VERSION) throw new SerializerException($"Invalid object version {ov}", new InvalidDataException());
            IAsymmetricPublicKey? key = null;
            byte[] keyData = ms.ReadArray<byte>(ssv, minLen: 1, maxLen: AsymmetricKeyBase.MaxArrayLength);
            try
            {
                key = AsymmetricKeyBase.Import<IAsymmetricPublicKey>(keyData);
                PublicKey = key;
            }
            catch
            {
                key?.Dispose();
                keyData?.Clear();
                throw;
            }
            Created = new DateTime(ms.ReadNumber<long>(ssv));
            Expires = new DateTime(ms.ReadNumber<long>(ssv));
            Attributes = ms.ReadDict<string, string>(maxLen: byte.MaxValue);
            Signer = ms.ReadSerializedNullable<AsymmetricSignedPublicKey>(ssv);
            CounterSigner = ms.ReadSerializedNullable<AsymmetricSignedPublicKey>(ssv);
        }

        /// <summary>
        /// Delegate for root key trust validation
        /// </summary>
        /// <param name="id">Root public key ID</param>
        /// <returns>Is trusted?</returns>
        public delegate bool RootTrust_Delegate(byte[] id);

        /// <summary>
        /// Delegate for root key trust validation
        /// </summary>
        /// <param name="id">Root public key ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Is trusted?</returns>
        public delegate Task<bool> RootTrustAsync_Delegate(byte[] id, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for a public key store
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        /// <returns>Public key</returns>
        public delegate AsymmetricSignedPublicKey? SignedPublicKeyStore_Delegate(byte[] id);

        /// <summary>
        /// Delegate for a public key store
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Public key</returns>
        public delegate Task<AsymmetricSignedPublicKey?> SignedPublicKeyStoreAsync_Delegate(byte[] id, CancellationToken cancellationToken);

        /// <summary>
        /// Delegate for signed public key revocation validation
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        /// <returns>If the key was revoked</returns>
        public delegate bool SignedPublicKeyRevocation_Delegate(byte[] id);

        /// <summary>
        /// Delegate for signed public key revocation validation
        /// </summary>
        /// <param name="id">Signed public key ID</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the key was revoked</returns>
        public delegate Task<bool> SignedPublicKeyRevocationAsync_Delegate(byte[] id, CancellationToken cancellationToken);

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="key">Key</param>
        public static implicit operator byte[](in AsymmetricSignedPublicKey key) => key.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator AsymmetricSignedPublicKey(in byte[] data) => data.ToObject<AsymmetricSignedPublicKey>();
    }
}
