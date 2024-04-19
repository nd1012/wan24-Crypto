using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a PAKE request factory
    /// </summary>
    public interface IPakeHttpRequestFactory : IDisposableObject
    {
        /// <summary>
        /// Encryption options (won't be cleared)
        /// </summary>
        CryptoOptions Options { get; }
        /// <summary>
        /// Create a request
        /// </summary>
        /// <param name="uri">URI</param>
        /// <param name="method">http method</param>
        /// <param name="path">Request path</param>
        /// <param name="param">Request parameters</param>
        /// <param name="headers">Headers</param>
        /// <param name="pakeResponse">Require PAKE response?</param>
        /// <returns>PAKE request (don't forget to dispose!)</returns>
        PakeRequest CreateRequest(
            in Uri uri,
            in HttpMethod method,
            in string path,
            in Dictionary<string, string>? param = null,
            in Dictionary<string, string[]>? headers = null,
            in bool pakeResponse = true
            );
        /// <summary>
        /// Create a request
        /// </summary>
        /// <param name="uri">URI</param>
        /// <param name="method">http method</param>
        /// <param name="path">Request path</param>
        /// <param name="content">Content (will be disposed!)</param>
        /// <param name="pakeResponse">Require PAKE response?</param>
        /// <returns>PAKE request (don't forget to dispose!)</returns>
        PakeRequest CreateRequest(
            in Uri uri,
            in HttpMethod method,
            in string path,
            in HttpContent content,
            in bool pakeResponse = true
            );
        /// <summary>
        /// Create a request
        /// </summary>
        /// <param name="uri">URI</param>
        /// <param name="method">http method</param>
        /// <param name="path">Request path</param>
        /// <param name="content">Content (will be disposed!)</param>
        /// <param name="pakeResponse">Require PAKE response?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE request (don't forget to dispose!)</returns>
        Task<PakeRequest> CreateRequestAsync(
            Uri uri,
            HttpMethod method,
            string path,
            HttpContent content,
            bool pakeResponse = true,
            CancellationToken cancellationToken = default
            );
        /// <summary>
        /// Create a request
        /// </summary>
        /// <param name="uri">URI</param>
        /// <param name="method">http method</param>
        /// <param name="path">Request path</param>
        /// <param name="body">Request body (won't be disposed)</param>
        /// <param name="longRunning">If the sending process will take longer time</param>
        /// <param name="headers">Headers</param>
        /// <param name="pakeResponse">Require PAKE response?</param>
        /// <param name="scheduler">Task scheduler to use</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE request (don't forget to dispose!)</returns>
        PakeRequest CreateRequest(
            in Uri uri,
            in HttpMethod method,
            in string path,
            in Stream body,
            in bool longRunning,
            in Dictionary<string, string[]>? headers = null,
            in bool pakeResponse = true,
            in TaskScheduler? scheduler = null,
            in CancellationToken cancellationToken = default
            );
        /// <summary>
        /// Create a request
        /// </summary>
        /// <param name="uri">URI</param>
        /// <param name="method">http method</param>
        /// <param name="path">Request path</param>
        /// <param name="body">Request body (won't be disposed)</param>
        /// <param name="headers">Headers</param>
        /// <param name="pakeResponse">Require PAKE response?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE request (don't forget to dispose!)</returns>
        Task<PakeRequest> CreateRequestAsync(
            Uri uri,
            HttpMethod method,
            string path,
            Stream body,
            Dictionary<string, string[]>? headers = null,
            bool pakeResponse = true,
            CancellationToken cancellationToken = default
            );
    }
}
