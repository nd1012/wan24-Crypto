using System.ComponentModel.DataAnnotations;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

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
        public byte[] Export()
        {
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

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        protected override void Serialize(Stream stream)
        {
            stream.WriteNumber(Algorithm.Value)
                .WriteBytes(KeyData.Array);
        }

        /// <summary>
        /// Serialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteNumberAsync(Algorithm.Value, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(KeyData.Array, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="version">Serializer version</param>
        protected override void Deserialize(Stream stream, int version)
        {
            if (stream.ReadNumber<int>() != Algorithm.Value) throw new SerializerException("Asymmetric algorithm mismatch");
            KeyData?.Dispose();
            KeyData = new(stream.ReadBytes(version, minLen: 1, maxLen: ushort.MaxValue).Value);
        }

        /// <summary>
        /// Deserialize
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="version">Serializer version</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            if (await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext() != Algorithm.Value)
                throw new SerializerException("Asymmetric algorithm mismatch");
            KeyData?.Dispose();
            KeyData = new((await stream.ReadBytesAsync(version, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value);
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
            keyData = ms.ReadBytes(ssv, minLen: 1, maxLen: ushort.MaxValue).Value;
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
