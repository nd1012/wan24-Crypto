﻿using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE response extensions
    /// </summary>
    public static class PakeResponseExtensions
    {
        /// <summary>
        /// Get the PAKE response
        /// </summary>
        /// <param name="response">Response (won't be disposed)</param>
        /// <param name="key">PAKE session key that was used for the request (won't be cleared)</param>
        /// <param name="options">Crypto options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE response (don't forget to dispose!)</returns>
        public static Task<PakeResponse> GetPakeResponseAsync(
            this HttpResponseMessage response,
            byte[] key,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
            => GetPakeResponseAsync<PakeResponse.PakeResponseDto>(response, key, options, cancellationToken);

        /// <summary>
        /// Get the PAKE response
        /// </summary>
        /// <typeparam name="T">PAKE response DTO type</typeparam>
        /// <param name="response">Response (won't be disposed)</param>
        /// <param name="key">PAKE session key that was used for the request (won't be cleared)</param>
        /// <param name="options">Crypto options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>PAKE response (don't forget to dispose!)</returns>
        public static async Task<PakeResponse> GetPakeResponseAsync<T>(
            this HttpResponseMessage response,
            byte[] key,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
            where T : PakeResponse.PakeResponseDto
        {
            response.EnsureSuccessStatusCode();
            if (!(response.Content.Headers.ContentType?.MediaType?.Equals(Constants.PAKE_RESPONSE_MIME_TYPE, StringComparison.OrdinalIgnoreCase) ?? false))
                throw new InvalidDataException("Invalid content type (PAKE response expected)");
            Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).DynamicContext();
            await using(body.DynamicContext())
                return await PakeResponse.CreateAsync<T>(body, key, options, cancellationToken).DynamicContext();
        }
    }
}
