using System.Net.Http.Headers;
using wan24.Core;

namespace wan24.Crypto
{
    // Internals
    public sealed partial class PakeHttpRequestFactory
    {
        /// <inheritdoc/>
        protected override PakeRequest.PakeRequestDto CreateDto(
            in HttpMethod method,
            in string path,
            in Dictionary<string, string[]>? headers,
            in Stream? stream,
            in bool pakeResponse)
            => new()
            {
                Method = method.Method,
                Path = path,
                Headers = headers,
                PakeResponse = pakeResponse
            };
    }

    public partial class PakeHttpRequestFactory<T> where T : PakeRequest.PakeRequestDto
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
