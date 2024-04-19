using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="PakeRequest"/> extensions
    /// </summary>
    public static class PakeRequestExtensions
    {
        /// <summary>
        /// Send a PAKE request
        /// </summary>
        /// <param name="client">Client</param>
        /// <param name="method">Method</param>
        /// <param name="path">Path</param>
        /// <param name="param">Parameters</param>
        /// <param name="headers">Headers</param>
        /// <param name="uri">Base URI (required, if <see cref="HttpClient.BaseAddress"/> wasn't set)</param>
        /// <param name="requestFactory">PAKE http request factory (required, if <see cref="PakeHttpRequestFactory.Instance"/> wasn't set; won't be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE response</returns>
        public static async Task<PakeResponse> SendPakeAsync(
            this HttpClient client,
            HttpMethod method,
            string path,
            Dictionary<string, string>? param = null,
            Dictionary<string, string[]>? headers = null,
            Uri? uri = null,
            IPakeHttpRequestFactory? requestFactory = null,
            CancellationToken cancellationToken = default
            )
        {
            uri ??= client.BaseAddress ?? throw new ArgumentNullException(nameof(uri));
            requestFactory ??= PakeHttpRequestFactory.Instance ?? throw new ArgumentNullException(nameof(requestFactory));
            PakeRequest request = requestFactory.CreateRequest(uri, method, path, param, headers);
            await using (request.DynamicContext())
            {
                HttpResponseMessage response = await client.SendAsync(request.Request, cancellationToken).DynamicContext();
                try
                {
                    PakeResponse res = await response.GetPakeResponseAsync(request.Key, requestFactory.Options.GetCopy(), cancellationToken).DynamicContext();
                    res.RegisterForDispose(response);
                    return res;
                }
                catch
                {
                    response.Dispose();
                    throw;
                }
            }
        }

        /// <summary>
        /// Send a PAKE request
        /// </summary>
        /// <param name="client">Client</param>
        /// <param name="method">Method</param>
        /// <param name="path">Path</param>
        /// <param name="content">Content (will be disposed!)</param>
        /// <param name="uri">Base URI (required, if <see cref="HttpClient.BaseAddress"/> wasn't set)</param>
        /// <param name="requestFactory">PAKE http request factory (required, if <see cref="PakeHttpRequestFactory.Instance"/> wasn't set; won't be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE response</returns>
        public static async Task<PakeResponse> SendPakeAsync(
            this HttpClient client,
            HttpMethod method,
            string path,
            HttpContent content,
            Uri? uri = null,
            IPakeHttpRequestFactory? requestFactory = null,
            CancellationToken cancellationToken = default
            )
        {
            try
            {
                uri ??= client.BaseAddress ?? throw new ArgumentNullException(nameof(uri));
                requestFactory ??= PakeHttpRequestFactory.Instance ?? throw new ArgumentNullException(nameof(requestFactory));
                PakeRequest request = await requestFactory.CreateRequestAsync(uri, method, path, content, cancellationToken: cancellationToken).DynamicContext();
                await using (request.DynamicContext())
                {
                    HttpResponseMessage response = await client.SendAsync(request.Request, cancellationToken).DynamicContext();
                    try
                    {
                        PakeResponse res = await response.GetPakeResponseAsync(request.Key, requestFactory.Options.GetCopy(), cancellationToken).DynamicContext();
                        res.RegisterForDispose(response);
                        return res;
                    }
                    catch
                    {
                        response.Dispose();
                        throw;
                    }
                }
            }
            catch
            {
                content.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Send a PAKE request
        /// </summary>
        /// <param name="client">Client</param>
        /// <param name="method">Method</param>
        /// <param name="path">Path</param>
        /// <param name="body">Request body stream (won't be disposed)</param>
        /// <param name="longRunning">If the sending process will take longer time</param>
        /// <param name="headers">Headers</param>
        /// <param name="uri">Base URI (required, if <see cref="HttpClient.BaseAddress"/> wasn't set)</param>
        /// <param name="requestFactory">PAKE http request factory (required, if <see cref="PakeHttpRequestFactory.Instance"/> wasn't set; won't be disposed)</param>
        /// <param name="scheduler">Task scheduler to use</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE response</returns>
        public static async Task<PakeResponse> SendPakeAsync(
            this HttpClient client,
            HttpMethod method,
            string path,
            Stream body,
            bool longRunning,
            Dictionary<string, string[]>? headers = null,
            Uri? uri = null,
            IPakeHttpRequestFactory? requestFactory = null,
            TaskScheduler? scheduler = null,
            CancellationToken cancellationToken = default
            )
        {
            uri ??= client.BaseAddress ?? throw new ArgumentNullException(nameof(uri));
            requestFactory ??= PakeHttpRequestFactory.Instance ?? throw new ArgumentNullException(nameof(requestFactory));
            PakeRequest request = requestFactory.CreateRequest(
                uri, 
                method, 
                path, 
                body,
                longRunning,
                headers,
                pakeResponse: true,
                scheduler, 
                cancellationToken
                );
            await using (request.DynamicContext())
            {
                HttpResponseMessage response = await client.SendAsync(request.Request, cancellationToken).DynamicContext();
                try
                {
                    PakeResponse res = await response.GetPakeResponseAsync(request.Key, requestFactory.Options.GetCopy(), cancellationToken).DynamicContext();
                    res.RegisterForDispose(response);
                    return res;
                }
                catch
                {
                    response.Dispose();
                    throw;
                }
            }
        }

        /// <summary>
        /// Send a PAKE request
        /// </summary>
        /// <param name="client">Client</param>
        /// <param name="method">Method</param>
        /// <param name="path">Path</param>
        /// <param name="body">Request body (won't be disposed)</param>
        /// <param name="headers">Headers</param>
        /// <param name="uri">Base URI (required, if <see cref="HttpClient.BaseAddress"/> wasn't set)</param>
        /// <param name="requestFactory">PAKE http request factory (required, if <see cref="PakeHttpRequestFactory.Instance"/> wasn't set; won't be disposed)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE response</returns>
        public static async Task<PakeResponse> SendPakeAsync(
            this HttpClient client,
            HttpMethod method,
            string path,
            Stream body,
            Dictionary<string, string[]>? headers = null,
            Uri? uri = null,
            IPakeHttpRequestFactory? requestFactory = null,
            CancellationToken cancellationToken = default
            )
        {
            uri ??= client.BaseAddress ?? throw new ArgumentNullException(nameof(uri));
            requestFactory ??= PakeHttpRequestFactory.Instance ?? throw new ArgumentNullException(nameof(requestFactory));
            PakeRequest request = await requestFactory.CreateRequestAsync(uri, method, path, body, headers, cancellationToken: cancellationToken).DynamicContext();
            await using (request.DynamicContext())
            {
                HttpResponseMessage response = await client.SendAsync(request.Request, cancellationToken).DynamicContext();
                try
                {
                    PakeResponse res = await response.GetPakeResponseAsync(request.Key, requestFactory.Options.GetCopy(), cancellationToken).DynamicContext();
                    res.RegisterForDispose(response);
                    return res;
                }
                catch
                {
                    response.Dispose();
                    throw;
                }
            }
        }
    }
}
