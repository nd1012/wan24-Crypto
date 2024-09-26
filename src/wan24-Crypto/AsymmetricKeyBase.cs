using System.ComponentModel.DataAnnotations;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;
using static wan24.Core.TranslationHelper;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for an asymmetric key
    /// </summary>
    public abstract record class AsymmetricKeyBase : DisposableStreamSerializerRecordBase, IAsymmetricKey
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="algorithm">Algorithm name</param>
        protected AsymmetricKeyBase(string algorithm) : base(VERSION) => Algorithm = AsymmetricHelper.GetAlgorithm(algorithm);

        /// <summary>
        /// Max. array length in serialized data in bytes
        /// </summary>
        public static int MaxArrayLength { get; set; } = ushort.MaxValue << 2;

        /// <inheritdoc/>
        [CountLimit(HashSha512Algorithm.HASH_LENGTH)]
        public abstract byte[] ID { get; }

        /// <inheritdoc/>
        public IAsymmetricAlgorithm Algorithm { get; }

        /// <inheritdoc/>
        [Range(1, int.MaxValue)]
        public abstract int Bits { get; }

        /// <inheritdoc/>
        [NoValidation, SensitiveData]
        public SecureByteArray KeyData { get; protected set; } = null!;

        /// <inheritdoc/>
        public virtual IEnumerable<Status> State
        {
            get
            {
                yield return new(__("Type"), GetType(), __("Asymmetric key CLR type"));
                yield return new(__("ID base64"), ID.GetBase64String(), __("base64 encoded key ID"));
                yield return new(__("ID hex"), Convert.ToHexString(ID), __("Hexadecimal encoded key ID"));
                yield return new(__("Key size"), Bits, __("The key size in bits"));
                yield return new(__("Key length"), KeyData?.Length, __("The key data length in bytes"));
                yield return new(__("Algorithm display name"), Algorithm.DisplayName, __("The algorithm display name"));
                yield return new(__("Algorithm name"), Algorithm.Name, __("The algorithm name"));
                yield return new(__("Algorithm value"), Algorithm.Value, __("The algorithm value"));
                yield return new(__("Key exchange"), Algorithm.CanExchangeKey, __("If the algorithm can be used for key exchange"));
                yield return new(__("Signature"), Algorithm.CanSign, __("If the algorithm can be used for digital signature"));
            }
        }

        /// <inheritdoc/>
        public byte[] Export()
        {
            // Export full key information
            using MemoryPoolStream ms = new()
            {
                CleanReturned = true
            };
            ms.WriteSerializerVersion()
                .WriteString(Algorithm.Name)
                .Write(this is IAsymmetricPrivateKey)
                .WriteBytes(KeyData.Array);
            return ms.ToArray();
        }

        /// <inheritdoc/>
        public override string ToString() => $"Asymmetric key {GetType()} (algorithm \"{Algorithm.Name}\" with {Bits} bits key length)";

        /// <summary>
        /// Ensure PQC requirement
        /// </summary>
        /// <param name="throwIfRequirementMismatch">Throw an axception if the PQC requirement does not match?</param>
        /// <returns></returns>
        /// <exception cref="CryptographicException">The PQC requirement does not match</exception>
        protected virtual bool EnsurePqcRequirement(in bool throwIfRequirementMismatch = true)
        {
            if (!Algorithm.IsPostQuantum && CryptoHelper.StrictPostQuantumSafety)
            {
                if (!throwIfRequirementMismatch) return false;
                throw CryptographicException.From(new InvalidOperationException($"Post quantum safety-forced - {Algorithm.DisplayName} isn't post quantum-safe"));
            }
            return true;
        }

        /// <summary>
        /// Ensure using an allowed elliptic curve
        /// </summary>
        /// <param name="throwIfDenied">Throw an axception if the used curve was denied?</param>
        /// <returns></returns>
        /// <exception cref="CryptographicException">The used elliptic curve was denieds</exception>
        protected virtual bool EnsureAllowedCurve(in bool throwIfDenied = true)
        {
            if (!Algorithm.IsEllipticCurveAlgorithm) return false;
            if (Algorithm.IsEllipticCurveAlgorithm && !EllipticCurves.IsCurveAllowed(Bits))
            {
                if (!throwIfDenied) return false;
                throw CryptographicException.From(new InvalidOperationException($"Elliptic curve with {Bits} bits key size was denied"));
            }
            return true;
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            // Export minimal key information (which ensures correct serialized data when deserializing)
            stream.WriteNumber(Algorithm.Value)
                .WriteBytes(KeyData.Array);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            // Export minimal key information (which ensures correct serialized data when deserializing)
            await stream.WriteNumberAsync(Algorithm.Value, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(KeyData.Array, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            if (stream.ReadNumber<int>() != Algorithm.Value) throw new SerializerException("Asymmetric algorithm mismatch");
            KeyData?.Dispose();
            KeyData = new(stream.ReadArray<byte>(version, minLen: 1, maxLen: MaxArrayLength));
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            if (await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext() != Algorithm.Value)
                throw new SerializerException("Asymmetric algorithm mismatch");
            KeyData?.Dispose();
            KeyData = new(await stream.ReadArrayAsync<byte>(version, minLen: 1, maxLen: MaxArrayLength, cancellationToken: cancellationToken).DynamicContext());
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => KeyData?.Dispose();

        /// <inheritdoc/>
        protected override Task DisposeCore()
        {
            KeyData?.Dispose();
            return Task.CompletedTask;
        }

        /// <summary>
        /// Create a key instance from exported key data
        /// </summary>
        /// <typeparam name="T">Asymmetric key type</typeparam>
        /// <param name="keyData">Key data</param>
        /// <returns>Key instance (don't forget to dispose)</returns>
        public static T Import<T>(byte[] keyData) where T : IAsymmetricKey
        {
            // Import full key information
            using MemoryStream ms = new(keyData);
            int ssv = ms.ReadSerializerVersion();
            string typeName = ms.ReadString(ssv, minLen: 1, maxLen: byte.MaxValue);
            Type type = AsymmetricHelper.Algorithms.ContainsKey(typeName)
                ? ms.ReadBool(ssv) 
                    ? AsymmetricHelper.GetAlgorithm(typeName).PrivateKeyType 
                    : AsymmetricHelper.GetAlgorithm(typeName).PublicKeyType
                : TypeHelper.Instance.GetType(typeName) ?? throw new InvalidDataException($"Failed to get serialized asymmetric key type \"{typeName}\"");// For downward compatibility
            if (!typeof(T).IsAssignableFrom(type) || type.IsAbstract || type.IsInterface)
                throw new InvalidDataException($"Type {type} isn't a valid asymmetric key type (expected {typeof(T)})");
            keyData = ms.ReadArray<byte>(ssv, minLen: 1, maxLen: MaxArrayLength);
            if (ms.Position != ms.Length) throw new InvalidDataException("Didn't use all available key data for deserializing asymmetric key");
            byte[] data = keyData.CloneArray();
            try
            {
                return (T)type.ConstructAuto(usePrivate: false, data) ?? throw new InvalidProgramException($"Failed to instance asymmetric key {type} ({typeof(T)})");
            }
            catch
            {
                data.Clear();
                throw;
            }
        }

        /// <summary>
        /// Create a key instance from exported key data
        /// </summary>
        /// <param name="keyData">Key data</param>
        /// <returns>Key instance (don't forget to dispose)</returns>
        public static IAsymmetricKey Import(byte[] keyData) => Import<IAsymmetricKey>(keyData);
    }
}
