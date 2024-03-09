using System.ComponentModel.DataAnnotations;
using System.Reflection;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE request
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="request">http request message (will be disposed!)</param>
    /// <param name="body">Request body stream (will be disposed!)</param>
    /// <param name="key">Encryption key (will be cleared!)</param>
    public sealed class PakeRequest(in HttpRequestMessage request, in Stream body, in byte[] key) : DisposableBase()
    {
        /// <summary>
        /// http request (will be disposed!)
        /// </summary>
        public HttpRequestMessage Request { get; } = request;

        /// <summary>
        /// Request body stream (will be disposed!)
        /// </summary>
        public Stream Body { get; } = body;

        /// <summary>
        /// Encryption key (will be cleared!)
        /// </summary>
        public byte[] Key { get; } = key;

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Key.Clear();
            Request.Dispose();
            Body.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            Key.Clear();
            Request.Dispose();
            await Body.DisposeAsync().DynamicContext();
        }

        /// <summary>
        /// PAKE request DTO
        /// </summary>
        public class PakeRequestDto : StreamSerializerBase
        {
            /// <summary>
            /// Object version
            /// </summary>
            public const int VERSION = 1;

            /// <summary>
            /// <see cref="Headers"/> property
            /// </summary>
            protected static readonly PropertyInfo HeadersProperty = typeof(PakeRequestDto).GetPropertyCached(nameof(Headers))!;

            /// <summary>
            /// Higher level object version
            /// </summary>
            protected readonly int HlVersion;
            /// <summary>
            /// Serialized higher level object version
            /// </summary>
            protected int? SerializedHlVersion = null;

            /// <summary>
            /// Constructor
            /// </summary>
            public PakeRequestDto() : base(VERSION) => HlVersion = 1;

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="hlVersion">Higher level object version</param>
            protected PakeRequestDto(in int hlVersion) : base(VERSION) => HlVersion = hlVersion;

            /// <summary>
            /// Request method
            /// </summary>
            [StringLength(byte.MaxValue), Required]
            public string Method { get; set; } = null!;

            /// <summary>
            /// Request path
            /// </summary>
            [StringLength(short.MaxValue), Required]
            public string Path { get; set; } = null!;

            /// <summary>
            /// Request headers
            /// </summary>
            [CountLimit(byte.MaxValue)]
            [ItemStringLength(byte.MaxValue, ItemValidationTargets.Key), ItemRequired(ItemValidationTargets.Key)]
            [ItemCountLimit(byte.MaxValue)]
            [ItemStringLength(short.MaxValue, ArrayLevel = 1)]
            public Dictionary<string, string[]>? Headers { get; set; }

            /// <summary>
            /// Request PAKE secured response?
            /// </summary>
            public bool PakeResponse { get; set; } = true;

            /// <inheritdoc/>
            protected override void Serialize(Stream stream)
            {
                stream.WriteNumber(HlVersion)
                    .WriteString(Method)
                    .WriteString(Path)
                    .WriteDictNullable(Headers)
                    .Write(PakeResponse);
            }

            /// <inheritdoc/>
            protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
            {
                await stream.WriteNumberAsync(HlVersion, cancellationToken).DynamicContext();
                await stream.WriteStringAsync(Method, cancellationToken).DynamicContext();
                await stream.WriteStringAsync(Path, cancellationToken).DynamicContext();
                await stream.WriteDictNullableAsync(Headers, cancellationToken).DynamicContext();
                await stream.WriteAsync(PakeResponse, cancellationToken).DynamicContext();
            }

            /// <inheritdoc/>
            protected override void Deserialize(Stream stream, int version)
            {
                SerializedHlVersion = stream.ReadNumber<int>(version);
                Method = stream.ReadString(version, minLen: 1, maxLen: byte.MaxValue);
                Path = stream.ReadString(version, minLen: 1, maxLen: short.MaxValue);
                Headers = stream.ReadDictNullable<string, string[]>(
                    version,
                    maxLen: byte.MaxValue,
                    keyOptions: HeadersProperty.GetKeySerializerOptions(stream, version, CancellationToken.None),
                    valueOptions: HeadersProperty.GetValueSerializerOptions(stream, version, CancellationToken.None)
                    );
                PakeResponse = stream.ReadBool(version);
            }

            /// <inheritdoc/>
            protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
            {
                SerializedHlVersion = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                Method = await stream.ReadStringAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                Path = await stream.ReadStringAsync(version, minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                Headers = await stream.ReadDictNullableAsync<string, string[]>(
                    version,
                    maxLen: byte.MaxValue,
                    keyOptions: HeadersProperty.GetKeySerializerOptions(stream, version, cancellationToken),
                    valueOptions: HeadersProperty.GetValueSerializerOptions(stream, version, cancellationToken),
                    cancellationToken: cancellationToken
                    ).DynamicContext();
                PakeResponse = await stream.ReadBoolAsync(version, cancellationToken: cancellationToken).DynamicContext();
            }
        }
    }
}
