using System.Security.Cryptography;
using wan24.Compression;
using wan24.Core;

namespace wan24.Crypto
{
    // Stream methods
    public partial record class EncryptionAlgorithmBase
    {
        /// <summary>
        /// Get an encryption stream
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="macStream">MAC stream</param>
        /// <param name="options">Options</param>
        /// <returns>Encryption stream, transform and MAC</returns>
        public virtual EncryptionStreams GetEncryptionStream(Stream rawData, Stream cipherData, MacStreams? macStream, CryptoOptions options)
        {
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                if (options.Password is null) throw new ArgumentException("Missing password", nameof(options));
                EncryptionHelper.GetDefaultOptions(options);
                Stream? stream = null;
                ICryptoTransform transform = GetEncryptor(macStream?.Stream ?? cipherData, options);
                try
                {
                    // Write the MAC
                    if (!RequireMacAuthentication && !options.ForceMacCoverWhole && macStream is not null)
                        try
                        {
                            options.Tracer?.WriteTrace("Writing the crypto header MAC");
                            macStream.Stream.Dispose();
                            long pos = cipherData.Position;
                            cipherData.Position = options.MacPosition;
                            options.Mac = macStream.Transform!.Hash ?? throw new InvalidProgramException();
                            if (options.UsingCounterMac) HybridAlgorithmHelper.ComputeMac(options);
                            cipherData.Write(options.Mac);
                            cipherData.Position = pos;
                        }
                        finally
                        {
                            macStream.Dispose();
                            macStream = null;
                        }
                    // Define the target cipher stream
                    stream = new WrapperStream(macStream?.Stream ?? cipherData, leaveOpen: macStream is not null || options.LeaveOpen);
                    // Apply RNG seeding
                    if (((options.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.CipherData) == RngSeedingTypes.CipherData)
                        stream = new RngSeedingStream(stream);
                    // Create the crypto stream
                    stream = new CryptoStream(
                        stream, 
                        transform, 
                        CryptoStreamMode.Write, 
                        leaveOpen: false
                        );
                    // Prepend a compression stream
                    if (options.Compressed)
                    {
                        options.Tracer?.WriteTrace($"Using compression {options.Compression?.Algorithm}");
                        options.Compression ??= CompressionHelper.GetDefaultOptions();
                        options.Compression.LeaveOpen = false;
                        CompressionHelper.WriteOptions(rawData, stream, options.Compression);
                        stream = stream.GetCompressionStream(options.Compression);
                    }
                    return new(stream, transform, macStream);
                }
                catch
                {
                    stream?.Dispose();
                    transform.Dispose();
                    macStream?.Dispose();
                    throw;
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Get an encryption stream
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="macStream">MAC stream</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Encryption stream, transform and MAC</returns>
        public virtual async Task<EncryptionStreams> GetEncryptionStreamAsync(
            Stream rawData,
            Stream cipherData,
            MacStreams? macStream,
            CryptoOptions options,
            CancellationToken cancellationToken = default
            )
        {
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                if (options.Password is null) throw new ArgumentException("Missing password", nameof(options));
                EncryptionHelper.GetDefaultOptions(options);
                Stream? stream = null;
                ICryptoTransform transform = await GetEncryptorAsync(macStream?.Stream ?? cipherData, options, cancellationToken).DynamicContext();
                try
                {
                    // Write the MAC
                    if (!RequireMacAuthentication && !options.ForceMacCoverWhole && macStream is not null)
                        try
                        {
                            options.Tracer?.WriteTrace("Writing the crypto header MAC");
                            macStream.Stream.Dispose();
                            long pos = cipherData.Position;
                            cipherData.Position = options.MacPosition;
                            options.Mac = macStream.Transform!.Hash ?? throw new InvalidProgramException();
                            if (options.UsingCounterMac) HybridAlgorithmHelper.ComputeMac(options);
                            await cipherData.WriteAsync(options.Mac, cancellationToken).DynamicContext();
                            cipherData.Position = pos;
                        }
                        finally
                        {
                            macStream.Dispose();
                            macStream = null;
                        }
                    // Define the target cipher stream
                    stream = new WrapperStream(macStream?.Stream ?? cipherData, leaveOpen: macStream is not null || options.LeaveOpen);
                    // Apply RNG seeding
                    if (((options.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.CipherData) == RngSeedingTypes.CipherData)
                        stream = new RngSeedingStream(stream);
                    // Create the crypto stream
                    stream = new CryptoStream(
                        stream,
                        transform,
                        CryptoStreamMode.Write,
                        leaveOpen: false
                        );
                    // Prepend a compression stream
                    if (options.Compressed)
                    {
                        options.Tracer?.WriteTrace($"Using compression {options.Compression?.Algorithm}");
                        options.Compression ??= CompressionHelper.GetDefaultOptions();
                        options.Compression.LeaveOpen = false;
                        await CompressionHelper.WriteOptionsAsync(rawData, stream, options.Compression, cancellationToken).DynamicContext();
                        stream = stream.GetCompressionStream(options.Compression);
                    }
                    return new(stream, transform, macStream);
                }
                catch
                {
                    if (stream is not null) await stream.DisposeAsync().DynamicContext();
                    transform.Dispose();
                    if (macStream is not null) await macStream.DisposeAsync().DynamicContext();
                    throw;
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw await CryptographicException.FromAsync(ex);
            }
        }

        /// <summary>
        /// Get a decryption stream
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="options">Options</param>
        /// <returns>Decryption stream and transform</returns>
        public virtual DecryptionStreams GetDecryptionStream(Stream cipherData, Stream rawData, CryptoOptions options)
        {
            try
            {
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                if (options.Password is null) throw new ArgumentException("Missing password", nameof(options));
                EncryptionHelper.GetDefaultOptions(options);
                Stream? stream = null;
                ICryptoTransform transform = GetDecryptor(cipherData, options);
                try
                {
                    // Authenticate the data which was red so far
                    if (options.MacIncluded && !RequireMacAuthentication && !options.ForceMacCoverWhole)
                    {
                        options.Tracer?.WriteTrace("Authenticating the crypto header using the MAC");
                        long pos = cipherData.Position;
                        cipherData.Position = options.MacPosition + options.Mac!.Length;
                        MacAlgorithmBase mac = MacHelper.GetAlgorithm(options.MacAlgorithm ?? MacHelper.DefaultAlgorithm.Name);
                        CryptoOptions macOptions = mac!.DefaultOptions;
                        macOptions.LeaveOpen = true;
                        using MacStreams macStream = mac.GetMacStream(options.Password ?? throw new InvalidOperationException("No password yet"), options: macOptions);
                        int read = (int)(pos - (options.MacPosition + options.Mac!.Length));
                        using (RentedArrayRefStruct<byte> buffer = new(Math.Min(Settings.BufferSize, read)))
                        {
                            for (int red = 1; red > 0 && read > 0; read -= red)
                            {
                                red = cipherData.Read(buffer.Span);
                                if (red > 0) macStream.Stream.Write(buffer.Span[..red]);
                            }
                            if (read > 0) throw new IOException($"Missing {read} bytes cipher data");
                        }
                        macStream.Stream.FlushFinalBlock();
                        byte[] redMac = options.Mac;
                        options.Mac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                        if (options.UsingCounterMac) HybridAlgorithmHelper.ComputeMac(options);
                        if (!options.Mac!.AsSpan().SlowCompare(redMac)) throw new InvalidDataException("MAC mismatch");
                        cipherData.Position = pos;
                    }
                    // Define the target cipher stream
                    stream = new WrapperStream(cipherData, leaveOpen: options.LeaveOpen);
                    // Apply RNG seeding
                    if (((options.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.CipherData) == RngSeedingTypes.CipherData)
                        stream = new RngSeedingStream(stream);
                    // Create the crypto stream
                    stream = new CryptoStream(stream, transform, CryptoStreamMode.Read, leaveOpen: false);
                    // Prepend a compression stream
                    if (options.Compressed)
                    {
                        options.Tracer?.WriteTrace("Reading compression options");
                        options.Compression = CompressionHelper.ReadOptions(stream, rawData, options.Compression);
                        options.Tracer?.WriteTrace($"Using compression {options.Compression.Algorithm}");
                        options.Compression.MaxUncompressedDataLength = options.MaxUncompressedDataLength;
                        options.Tracer?.WriteTrace($"Maximum uncompressed data length {(options.MaxUncompressedDataLength < 1 ? "unlimited" : options.MaxUncompressedDataLength.ToString())}");
                        stream = stream.GetDecompressionStream(options.Compression);
                    }
                    return new(stream, transform);
                }
                catch
                {
                    stream?.Dispose();
                    transform.Dispose();
                    throw;
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Get a decryption stream
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Decryption stream and transform</returns>
        public virtual async Task<DecryptionStreams> GetDecryptionStreamAsync(
            Stream cipherData,
            Stream rawData,
            CryptoOptions options,
            CancellationToken cancellationToken = default
            )
        {
            try
            {
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                if (options.Password is null) throw new ArgumentException("Missing password", nameof(options));
                EncryptionHelper.GetDefaultOptions();
                Stream? stream = null;
                ICryptoTransform transform = await GetDecryptorAsync(cipherData, options, cancellationToken).DynamicContext();
                try
                {
                    // Authenticate the data which was red so far
                    if (options.MacIncluded && !RequireMacAuthentication && !options.ForceMacCoverWhole)
                    {
                        options.Tracer?.WriteTrace("Authenticating the crypto header using the MAC");
                        long pos = cipherData.Position;
                        cipherData.Position = options.MacPosition + options.Mac!.Length;
                        MacAlgorithmBase mac = MacHelper.GetAlgorithm(options.MacAlgorithm ?? MacHelper.DefaultAlgorithm.Name);
                        CryptoOptions macOptions = mac!.DefaultOptions;
                        macOptions.LeaveOpen = true;
                        using MacStreams macStream = mac.GetMacStream(options.Password ?? throw new InvalidOperationException("No password yet"), options: macOptions);
                        int read = (int)(pos - (options.MacPosition + options.Mac!.Length));
                        using (RentedArrayStruct<byte> buffer = new(Math.Min(Settings.BufferSize, read)))
                        {
                            for (int red = 1; red > 0 && read > 0; read -= red)
                            {
                                red = await cipherData.ReadAsync(buffer.Memory, cancellationToken).DynamicContext();
                                if (red > 0) macStream.Stream.Write(buffer.Span[..red]);
                            }
                            if (read > 0) throw new IOException($"Missing {read} bytes cipher data");
                        }
                        macStream.Stream.FlushFinalBlock();
                        byte[] redMac = options.Mac;
                        options.Mac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                        if (options.UsingCounterMac) HybridAlgorithmHelper.ComputeMac(options);
                        if (!options.Mac!.AsSpan().SlowCompare(redMac)) throw new InvalidDataException("MAC mismatch");
                        cipherData.Position = pos;
                    }
                    // Define the target cipher stream
                    stream = new WrapperStream(cipherData, leaveOpen: options.LeaveOpen);
                    // Apply RNG seeding
                    if (((options.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.CipherData) == RngSeedingTypes.CipherData)
                        stream = new RngSeedingStream(stream);
                    // Create the crypto stream
                    stream = new CryptoStream(stream, transform, CryptoStreamMode.Read, leaveOpen: false);
                    // Prepend a compression stream
                    if (options.Compressed)
                    {
                        options.Tracer?.WriteTrace("Reading compression options");
                        options.Compression = await CompressionHelper.ReadOptionsAsync(stream, rawData, options.Compression, cancellationToken).DynamicContext();
                        options.Tracer?.WriteTrace($"Using compression {options.Compression.Algorithm}");
                        options.Compression.MaxUncompressedDataLength = options.MaxUncompressedDataLength;
                        options.Tracer?.WriteTrace($"Maximum uncompressed data length {(options.MaxUncompressedDataLength < 1 ? "unlimited" : options.MaxUncompressedDataLength.ToString())}");
                        stream = stream.GetDecompressionStream(options.Compression);
                    }
                    return new(stream, transform);
                }
                catch
                {
                    stream?.Dispose();
                    transform.Dispose();
                    throw;
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw await CryptographicException.FromAsync(ex);
            }
        }
    }
}
