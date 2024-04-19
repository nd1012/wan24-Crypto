using System.Text;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Create request
    public partial class PakeHttpRequestFactory<T> where T : PakeRequest.PakeRequestDto
    {
        /// <inheritdoc/>
        public virtual PakeRequest CreateRequest(
            in Uri uri,
            in HttpMethod method,
            in string path,
            in Dictionary<string, string>? param = null,
            in Dictionary<string, string[]>? headers = null,
            in bool pakeResponse = true
            )
        {
            EnsureUndisposed();
            Stream? queryParameters = method.Method.IsLike(HttpMethod.Get.Method) && param is not null && param.Count > 0
                ? new MemoryStream(param.AsQueryString().GetBytes())
                : null;
            try
            {
                MemoryPoolStream bodyStream = null!;
                HttpRequestMessage request = null!;
                (PakeAuth auth, byte[] key) = Client.CreateAuth(DateTime.UtcNow.Ticks.GetBytes(), encryptPayload: true);
                try
                {
                    bodyStream = new()
                    {
                        Name = "PAKE request body"
                    };
                    bodyStream.WriteSerializerVersion()
                        .WriteSerialized(auth);
                    auth.Dispose();
                    using (MemoryPoolStream temp = new()
                    {
                        Name = "Temporary PAKE request body",
                        CleanReturned = true
                    })
                    {
                        temp.WriteSerialized(CreateDto(method, path, headers, queryParameters, pakeResponse));
                        queryParameters?.CopyTo(temp);
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
            catch
            {
                queryParameters?.Dispose();
                throw;
            }
        }

        /// <inheritdoc/>
        public virtual PakeRequest CreateRequest(
            in Uri uri,
            in HttpMethod method,
            in string path,
            in HttpContent content,
            in bool pakeResponse = true
            )
        {
            try
            {
                EnsureUndisposed();
                PooledTempStream bodyStream = null!;
                HttpRequestMessage request = null!;
                (PakeAuth auth, byte[] key) = Client.CreateAuth(DateTime.UtcNow.Ticks.GetBytes(), encryptPayload: true);
                try
                {
                    bodyStream = new()
                    {
                        Name = "PAKE request body"
                    };
                    bodyStream.WriteSerializerVersion()
                        .WriteSerialized(auth);
                    auth.Dispose();
                    using (PooledTempStream temp = new()
                    {
                        Name = "Temporary PAKE request body"
                    })
                    {
                        using (Stream contentStream = content.ReadAsStream())
                        {
                            temp.WriteSerialized(
                                CreateDto(
                                    method,
                                    path,
                                    new(content.Headers.Select(kvp => new KeyValuePair<string, string[]>(kvp.Key, [.. kvp.Value]))),
                                    contentStream,
                                    pakeResponse
                                    )
                                );
                            contentStream.CopyTo(temp);
                        }
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
            finally
            {
                content.Dispose();
            }
        }

        /// <inheritdoc/>
        public virtual async Task<PakeRequest> CreateRequestAsync(
            Uri uri,
            HttpMethod method,
            string path,
            HttpContent content,
            bool pakeResponse = true,
            CancellationToken cancellationToken = default
            )
        {
            try
            {
                EnsureUndisposed();
                PooledTempStream bodyStream = null!;
                HttpRequestMessage request = null!;
                (PakeAuth auth, byte[] key) = await Client.CreateAuthAsync(DateTime.UtcNow.Ticks.GetBytes(), encryptPayload: true).DynamicContext();
                try
                {
                    bodyStream = new()
                    {
                        Name = "PAKE request body"
                    };
                    bodyStream.WriteSerializerVersion()
                        .WriteSerialized(auth);
                    auth.Dispose();
                    using (PooledTempStream temp = new()
                    {
                        Name = "Temporary PAKE request body"
                    })
                    {
                        Stream contentStream = await content.ReadAsStreamAsync(cancellationToken).DynamicContext();
                        await using (contentStream.DynamicContext())
                        {
                            await temp.WriteSerializedAsync(
                                CreateDto(
                                    method,
                                    path,
                                    new(content.Headers.Select(kvp => new KeyValuePair<string, string[]>(kvp.Key, [.. kvp.Value]))),
                                    contentStream,
                                    pakeResponse
                                    ),
                                cancellationToken
                                ).DynamicContext();
                            await contentStream.CopyToAsync(temp, cancellationToken).DynamicContext();
                        }
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
            finally
            {
                content.Dispose();
            }
        }

        /// <inheritdoc/>
        public virtual PakeRequest CreateRequest(
            in Uri uri,
            in HttpMethod method,
            in string path,
            in Stream body,
            in bool longRunning,
            in Dictionary<string, string[]>? headers = null,
            in bool pakeResponse = true,
            in TaskScheduler? scheduler = null,
            in CancellationToken cancellationToken = default
            )
        {
            EnsureUndisposed();
            CombinedStream bodyStream = null!;
            MemoryPoolStream bodyHeader = null!;
            PakeRequestStream cipherStream = null!;
            HttpRequestMessage request = null!;
            EncryptionStreams cipher = null!;
            (PakeAuth auth, byte[] key) = Client.CreateAuth(DateTime.UtcNow.Ticks.GetBytes(), encryptPayload: true);
            try
            {
                // Create used streams
                bodyHeader = new()
                {
                    Name = "PAKE request body header",
                    CleanReturned = true
                };
                cipherStream = new(body, Settings.BufferSize, cancellationToken)
                {
                    Name = "PAKE request body cipher stream"
                };
                bodyStream = new(resetPosition: false, leaveOpen: false, bodyHeader, cipherStream)
                {
                    Name = "PAKE request body"
                };
                // Write the body header
                bodyHeader.WriteSerializerVersion()
                    .WriteSerialized(auth);
                auth.Dispose();
                bodyHeader.WriteSerialized(CreateDto(method, path, headers, body, pakeResponse));
                // Initialize the body cipher stream
                CryptoOptions options = Options.GetCopy();
                options.LeaveOpen = true;
                (options, _) = EncryptionHelper.WriteOptions(Stream.Null, bodyHeader, options);
                bodyHeader.Position = 0;
                cipher = EncryptionHelper.GetEncryptionStream(Stream.Null, cipherStream, macStream: null, options);
                cipherStream.SetCipher(cipher.CryptoStream, scheduler, longRunning);
                // Create the http request message
                request = new(HttpMethod.Post, uri)
                {
                    Content = new StreamContent(bodyStream)
                };
                request.Content.Headers.ContentType = PakeContentType;
                // Create the response
                PakeRequest res = new(request, bodyStream, key);
                res.RegisterForDispose(cipher);
                return res;
            }
            catch
            {
                auth.Dispose();
                key.Clear();
                bodyStream?.Dispose();
                bodyHeader?.Dispose();
                bodyStream?.Dispose();
                cipherStream?.Dispose();
                cipher?.Dispose();
                throw;
            }
        }

        /// <inheritdoc/>
        public virtual async Task<PakeRequest> CreateRequestAsync(
            Uri uri,
            HttpMethod method,
            string path,
            Stream body,
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
                bodyStream = new()
                {
                    Name = "PAKE request body"
                };
                await bodyStream.WriteSerializerVersionAsync(cancellationToken).DynamicContext();
                await bodyStream.WriteSerializedAsync(auth, cancellationToken).DynamicContext();
                auth.Dispose();
                using (PooledTempStream temp = new()
                {
                    Name = "Temporary PAKE request body"
                })
                {
                    await temp.WriteSerializedAsync(CreateDto(method, path, headers, body, pakeResponse), cancellationToken).DynamicContext();
                    await body.CopyToAsync(temp, cancellationToken).DynamicContext();
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
                if(bodyStream is not null) await bodyStream.DisposeAsync().DynamicContext();
                request?.Dispose();
                throw;
            }
        }
    }
}
