using System.Net.Http.Headers;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE http request factory
    /// </summary>
    public sealed class PakeHttpRequestFactory : PakeHttpRequestFactory<PakeRequest.PakeRequestDto>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="id">ID (will be cleared!)</param>
        /// <param name="key">Key (will be cleared!)</param>
        public PakeHttpRequestFactory(in byte[] id, in byte[] key) : base(id, key) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keySuite">Key suite (will be disposed!)</param>
        public PakeHttpRequestFactory(in ISymmetricKeySuite keySuite) : base(keySuite) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="client">PAKE client (will be disposed!)</param>
        public PakeHttpRequestFactory(in FastPakeAuthClient client) : base(client) { }

        /// <inheritdoc/>
        protected override PakeRequest.PakeRequestDto CreateDto(in HttpMethod method, in string path, in Dictionary<string, string[]>? headers, in Stream? stream, in bool pakeResponse)
            => new()
            {
                Method = method.Method,
                Path = path,
                Headers = headers,
                PakeResponse = pakeResponse
            };
    }

    /// <summary>
    /// PAKE http request factory
    /// </summary>
    /// <typeparam name="T">Pake request DTO type</typeparam>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="client">PAKE client (will be disposed!)</param>
    public class PakeHttpRequestFactory<T>(in FastPakeAuthClient client) : DisposableBase() where T : PakeRequest.PakeRequestDto
    {
        /// <summary>
        /// PAKE content type
        /// </summary>
        protected static readonly MediaTypeHeaderValue PakeContentType = new(Constants.PAKE_REQUEST_MIME_TYPE);

        /// <summary>
        /// PAKE client
        /// </summary>
        protected readonly FastPakeAuthClient Client = client;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="id">ID (will be cleared!)</param>
        /// <param name="key">Key (will be cleared!)</param>
        public PakeHttpRequestFactory(in byte[] id, in byte[] key) : this(new SymmetricKeySuite(key, id)) { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="keySuite">Key suite (will be disposed!)</param>
        public PakeHttpRequestFactory(in ISymmetricKeySuite keySuite) : this(new FastPakeAuthClient(keySuite)) { }

        /// <summary>
        /// Encryption options
        /// </summary>
        public CryptoOptions Options { get; init; } = EncryptionHelper.GetDefaultOptions();

        /// <summary>
        /// Create a request
        /// </summary>
        /// <param name="uri">URI</param>
        /// <param name="method">http method</param>
        /// <param name="path">Request path</param>
        /// <param name="body">Request body (may be disposed after the request has been created)</param>
        /// <param name="headers">Request http headers</param>
        /// <param name="pakeResponse">Awaiting PAKE response?</param>
        /// <returns>PAKE request (don't forget to dispose!)</returns>
        public virtual PakeRequest CreateRequest(
            in Uri uri, 
            in HttpMethod method, 
            in string path, 
            in Stream? body = null, 
            in Dictionary<string, string[]>? headers = null, 
            in bool pakeResponse = true
            )
        {
            EnsureUndisposed();
            PooledTempStream bodyStream = null!;
            HttpRequestMessage request = null!;
            (PakeAuth auth, byte[] key) = Client.CreateAuth(DateTime.UtcNow.Ticks.GetBytes(), encryptPayload: true);
            try
            {
                bodyStream = new();
                bodyStream.WriteSerializerVersion()
                    .WriteSerialized(auth);
                auth.Dispose();
                using (PooledTempStream temp = new())
                {
                    temp.WriteSerialized(CreateDto(method, path, headers, body, pakeResponse));
                    body?.CopyTo(temp);
                    temp.Position = 0;
                    CryptoOptions options = Options.GetCopy();
                    options.LeaveOpen = true;
                    EncryptionHelper.Encrypt(temp, bodyStream, key, options);
                }
                bodyStream.Position = 0;
                request = new(HttpMethod.Post, uri)
                {
                    Content = new StreamContent(bodyStream)
                };
                request.Content.Headers.ContentType = PakeContentType;
                return new(request, bodyStream, key);
            }
            catch
            {
                auth.Dispose();
                key.Clear();
                bodyStream?.Dispose();
                request?.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Create a request
        /// </summary>
        /// <param name="uri">URI</param>
        /// <param name="method">http method</param>
        /// <param name="path">Request path</param>
        /// <param name="body">Request body (may be disposed after the request has been created)</param>
        /// <param name="headers">Request http headers</param>
        /// <param name="pakeResponse">Awaiting PAKE response?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE request (don't forget to dispose!)</returns>
        public virtual async Task<PakeRequest> CreateRequestAsync(
            Uri uri,
            HttpMethod method,
            string path,
            Stream? body = null,
            Dictionary<string, string[]>? headers = null,
            bool pakeResponse = true,
            CancellationToken cancellationToken = default
            )
        {
            EnsureUndisposed();
            PooledTempStream bodyStream = null!;
            HttpRequestMessage request = null!;
            (PakeAuth auth, byte[] key) = await Client.CreateAuthAsync(DateTime.UtcNow.Ticks.GetBytes(), encryptPayload: true).DynamicContext();
            try
            {
                bodyStream = new();
                await bodyStream.WriteSerializerVersionAsync(cancellationToken).DynamicContext();
                await bodyStream.WriteSerializedAsync(auth, cancellationToken).DynamicContext();
                auth.Dispose();
                using (PooledTempStream temp = new())
                {
                    await temp.WriteSerializedAsync(CreateDto(method, path, headers, body, pakeResponse), cancellationToken).DynamicContext();
                    if (body is not null) await body.CopyToAsync(temp, cancellationToken).DynamicContext();
                    temp.Position = 0;
                    CryptoOptions options = Options.GetCopy();
                    options.LeaveOpen = true;
                    await EncryptionHelper.EncryptAsync(temp, bodyStream, key, options, cancellationToken: cancellationToken).DynamicContext();
                }
                bodyStream.Position = 0;
                request = new(HttpMethod.Post, uri)
                {
                    Content = new StreamContent(bodyStream)
                };
                request.Content.Headers.ContentType = PakeContentType;
                return new(request, bodyStream, key);
            }
            catch
            {
                auth.Dispose();
                key.Clear();
                if (bodyStream is not null) await bodyStream.DisposeAsync().DynamicContext();
                request?.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Create a PAKE request DTO
        /// </summary>
        /// <param name="method">http method</param>
        /// <param name="path">Request path</param>
        /// <param name="headers">Request http headers</param>
        /// <param name="body">Body stream</param>
        /// <param name="pakeResponse">Awaiting PAKE response?</param>
        /// <returns>PAKE request DTO</returns>
        protected virtual T CreateDto(in HttpMethod method, in string path, in Dictionary<string, string[]>? headers, in Stream? body, in bool pakeResponse)
        {
            T res = typeof(T).ConstructAuto() as T ?? throw new InvalidProgramException($"Failed to instance {typeof(T)}");
            res.Method = method.Method;
            res.Path = path;
            res.Headers = headers;
            res.PakeResponse = pakeResponse;
            return res;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing) => Client.Dispose();

        /// <inheritdoc/>
        protected override async Task DisposeCore() => await Client.DisposeAsync().DynamicContext();
    }
}
