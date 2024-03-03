using System.Net;
using System.Reflection;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE http response
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="response">PAKE response message</param>
    /// <param name="body">Response body stream (will be disposed!)</param>
    public sealed class PakeResponse(in PakeResponse.PakeResponseDto response, in DecryptionStreams body) : DisposableBase()
    {
        /// <summary>
        /// PAKE response message
        /// </summary>
        public PakeResponseDto Response { get; } = response;

        /// <summary>
        /// Response body
        /// </summary>
        public DecryptionStreams Body { get; } = body;

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => Body.Dispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await Body.DisposeAsync().DynamicContext();

        /// <summary>
        /// Create a PAKE response from a stream
        /// </summary>
        /// <param name="stream">Source stream</param>
        /// <param name="key">PAKE session key</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE response</returns>
        public static Task<PakeResponse> CreateAsync(
            Stream stream,
            byte[] key,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
            => CreateAsync<PakeResponseDto>(stream, key, options, cancellationToken);

        /// <summary>
        /// Create a PAKE response from a stream
        /// </summary>
        /// <typeparam name="T">PAKE response DTO type</typeparam>
        /// <param name="stream">Source stream (will be disposed!)</param>
        /// <param name="key">PAKE session key</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE response (don't forget to dispose!)</returns>
        public static async Task<PakeResponse> CreateAsync<T>(
            Stream stream,
            byte[] key,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
            where T : PakeResponseDto
        {
            options = options?.GetCopy() ?? EncryptionHelper.GetDefaultOptions();
            options.LeaveOpen = false;
            DecryptionStreams decipher = null!;
            try
            {
                options = await EncryptionHelper.ReadOptionsAsync(stream, Stream.Null, key, options, cancellationToken).DynamicContext();
                decipher = await EncryptionHelper.GetDecryptionStreamAsync(stream, Stream.Null, options, cancellationToken).DynamicContext();
                return new(
                    await decipher.CryptoStream.ReadSerializedAsync<T>(
                        await decipher.CryptoStream.ReadSerializerVersionAsync(cancellationToken).DynamicContext(),
                        cancellationToken
                        ).DynamicContext(),
                    decipher
                    );
            }
            catch
            {
                await stream.DisposeAsync().DynamicContext();
                if (decipher is not null) await decipher.DisposeAsync().DynamicContext();
                throw;
            }
            finally
            {
                options.Clear();
            }
        }

        /// <summary>
        /// PAKE response DTO
        /// </summary>
        public class PakeResponseDto : StreamSerializerBase
        {
            /// <summary>
            /// Object version
            /// </summary>
            public const int VERSION = 1;

            /// <summary>
            /// <see cref="Headers"/> property
            /// </summary>
            protected static readonly PropertyInfo HeadersProperty = typeof(PakeResponseDto).GetPropertyCached(nameof(Headers))!;

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
            public PakeResponseDto() : base(VERSION) => HlVersion = 1;

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="hlVersion">Higher level object version</param>
            protected PakeResponseDto(in int hlVersion) : base(VERSION) => HlVersion = hlVersion;

            /// <summary>
            /// http status
            /// </summary>
            public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

            /// <summary>
            /// Request headers
            /// </summary>
            [CountLimit(byte.MaxValue)]
            [ItemStringLength(byte.MaxValue, ItemValidationTargets.Key), ItemRequired(ItemValidationTargets.Key)]
            [ItemCountLimit(byte.MaxValue)]
            [ItemStringLength(short.MaxValue, ArrayLevel = 1)]
            public Dictionary<string, string[]>? Headers { get; set; }

            /// <inheritdoc/>
            protected override void Serialize(Stream stream)
            {
                stream.WriteNumber(HlVersion)
                    .WriteEnum(Status)
                    .WriteDictNullable(Headers);
            }

            /// <inheritdoc/>
            protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
            {
                await stream.WriteNumberAsync(HlVersion, cancellationToken).DynamicContext();
                await stream.WriteEnumAsync(Status, cancellationToken).DynamicContext();
                await stream.WriteDictNullableAsync(Headers, cancellationToken).DynamicContext();
            }

            /// <inheritdoc/>
            protected override void Deserialize(Stream stream, int version)
            {
                SerializedHlVersion = stream.ReadNumber<int>(version);
                Status = stream.ReadEnum<HttpStatusCode>(version);
                Headers = stream.ReadDictNullable<string, string[]>(
                    version,
                    maxLen: byte.MaxValue,
                    keyOptions: HeadersProperty.GetKeySerializerOptions(stream, version, CancellationToken.None),
                    valueOptions: HeadersProperty.GetValueSerializerOptions(stream, version, CancellationToken.None)
                    );
            }

            /// <inheritdoc/>
            protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
            {
                SerializedHlVersion = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                Status = await stream.ReadEnumAsync<HttpStatusCode>(version, cancellationToken: cancellationToken).DynamicContext();
                Headers = await stream.ReadDictNullableAsync<string, string[]>(
                    version, 
                    maxLen: byte.MaxValue,
                    keyOptions: HeadersProperty.GetKeySerializerOptions(stream, version, cancellationToken),
                    valueOptions: HeadersProperty.GetValueSerializerOptions(stream, version, cancellationToken),
                    cancellationToken: cancellationToken
                    ).DynamicContext();
            }
        }
    }
}
