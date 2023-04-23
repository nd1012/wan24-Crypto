using System.Security.Cryptography;
using wan24.Compression;
using wan24.Core;

namespace wan24.Crypto
{
    // Stream methods
    public partial class EncryptionAlgorithmBase
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
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                if (options.Password == null) throw new ArgumentException("Missing password", nameof(options));
                Stream? stream = null;
                ICryptoTransform transform = GetEncryptor(macStream?.Stream ?? cipherData, options);
                try
                {
                    // Write the MAC
                    if (!RequireMacAuthentication && !options.ForceMacCoverWhole && macStream != null)
                        try
                        {
                            macStream.Stream.Dispose();
                            long pos = cipherData.Position;
                            cipherData.Position = options.MacPosition;
                            byte[] mac = macStream.Transform!.Hash ?? throw new InvalidProgramException();
                            if (options.UsingCounterMac) mac = HybridAlgorithmHelper.ComputeMac(mac, options);
                            cipherData.Write(mac);
                            cipherData.Position = pos;
                        }
                        finally
                        {
                            macStream.Dispose();
                            macStream = null;
                        }
                    // Create the crypto stream
                    stream = new CryptoStream(macStream?.Stream ?? cipherData, transform, CryptoStreamMode.Write, leaveOpen: macStream != null || options.LeaveOpen);
                    // Prepend a compression stream
                    if (options.Compressed)
                    {
                        options.Compression = CompressionHelper.GetDefaultOptions(options.Compression);
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
                throw new CryptographicException(ex.Message, ex);
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
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                if (options.Password == null) throw new ArgumentException("Missing password", nameof(options));
                Stream? stream = null;
                ICryptoTransform transform = await GetEncryptorAsync(macStream?.Stream ?? cipherData, options, cancellationToken).DynamicContext();
                try
                {
                    // Write the MAC
                    if (!RequireMacAuthentication && !options.ForceMacCoverWhole && macStream != null)
                        try
                        {
                            macStream.Stream.Dispose();
                            long pos = cipherData.Position;
                            cipherData.Position = options.MacPosition;
                            byte[] mac = macStream.Transform!.Hash ?? throw new InvalidProgramException();
                            if (options.UsingCounterMac) mac = HybridAlgorithmHelper.ComputeMac(mac, options);
                            await cipherData.WriteAsync(mac, cancellationToken).DynamicContext();
                            cipherData.Position = pos;
                        }
                        finally
                        {
                            macStream.Dispose();
                            macStream = null;
                        }
                    // Create the crypto stream
                    stream = new CryptoStream(macStream?.Stream ?? cipherData, transform, CryptoStreamMode.Write, leaveOpen: macStream != null || options.LeaveOpen);
                    // Prepend a compression stream
                    if (options.Compressed)
                    {
                        options.Compression = CompressionHelper.GetDefaultOptions(options.Compression);
                        options.Compression.LeaveOpen = false;
                        await CompressionHelper.WriteOptionsAsync(rawData, stream, options.Compression, cancellationToken).DynamicContext();
                        stream = stream.GetCompressionStream(options.Compression);
                    }
                    return new(stream, transform, macStream);
                }
                catch
                {
                    if (stream != null) await stream.DisposeAsync().DynamicContext();
                    transform.Dispose();
                    if (macStream != null) await macStream.DisposeAsync().DynamicContext();
                    throw;
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
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
                if (options.Password == null) throw new ArgumentException("Missing password", nameof(options));
                Stream? stream = null;
                ICryptoTransform transform = GetDecryptor(cipherData, options);
                try
                {
                    // Authenticate the data which was red so far
                    if (options.MacIncluded && !RequireMacAuthentication && !options.ForceMacCoverWhole)
                    {
                        long pos = cipherData.Position;
                        cipherData.Position = options.MacPosition + options.Mac!.Length;
                        MacAlgorithmBase mac = MacHelper.GetAlgorithm(options.MacAlgorithm ?? MacHelper.DefaultAlgorithm.Name);
                        CryptoOptions macOptions = mac!.DefaultOptions;
                        macOptions.LeaveOpen = true;
                        using MacStreams macStream = mac.GetMacStream(options.Password ?? throw new CryptographicException("No password yet"), options: macOptions);
                        int read = (int)(pos - (options.MacPosition + options.Mac!.Length));
                        using (RentedArray<byte> buffer = new(Math.Min(Settings.BufferSize, read)))
                            for (int red; read > 0; read -= red)
                            {
                                red = cipherData.Read(buffer.Span);
                                if (red > 0) macStream.Stream.Write(buffer.Span.Slice(0, red));
                            }
                        macStream.Stream.FlushFinalBlock();
                        byte[] redMac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                        if (options.UsingCounterMac) redMac = HybridAlgorithmHelper.ComputeMac(redMac, options);
                        if (!options.Mac.AsSpan().SlowCompare(redMac)) throw new CryptographicException("MAC mismatch");
                        cipherData.Position = pos;
                    }
                    // Create the crypto stream
                    stream = new CryptoStream(cipherData, transform, CryptoStreamMode.Read, leaveOpen: options.LeaveOpen);
                    // Prepend a compression stream
                    if (options.Compressed)
                    {
                        (options.Compression, _, long uncompressedLength) = CompressionHelper.ReadOptions(stream, rawData, options.Compression);
                        options.Compression.LeaveOpen = false;
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
                throw new CryptographicException(ex.Message, ex);
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
                if (options.Password == null) throw new ArgumentException("Missing password", nameof(options));
                Stream? stream = null;
                ICryptoTransform transform = await GetDecryptorAsync(cipherData, options, cancellationToken).DynamicContext();
                try
                {
                    // Authenticate the data which was red so far
                    if (options.MacIncluded && !RequireMacAuthentication && !options.ForceMacCoverWhole)
                    {
                        long pos = cipherData.Position;
                        cipherData.Position = options.MacPosition + options.Mac!.Length;
                        MacAlgorithmBase mac = MacHelper.GetAlgorithm(options.MacAlgorithm ?? MacHelper.DefaultAlgorithm.Name);
                        CryptoOptions macOptions = mac!.DefaultOptions;
                        macOptions.LeaveOpen = true;
                        using MacStreams macStream = mac.GetMacStream(options.Password ?? throw new CryptographicException("No password yet"), options: macOptions);
                        int read = (int)(pos - (options.MacPosition + options.Mac!.Length));
                        using (RentedArray<byte> buffer = new(Math.Min(Settings.BufferSize, read)))
                            for (int red; read > 0; read -= red)
                            {
                                red = await cipherData.ReadAsync(buffer.Memory, cancellationToken).DynamicContext();
                                if (red > 0) macStream.Stream.Write(buffer.Span.Slice(0, red));
                            }
                        macStream.Stream.FlushFinalBlock();
                        byte[] redMac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                        if (options.UsingCounterMac) redMac = HybridAlgorithmHelper.ComputeMac(redMac, options);
                        if (!options.Mac.AsSpan().SlowCompare(redMac)) throw new CryptographicException("MAC mismatch");
                        cipherData.Position = pos;
                    }
                    // Create the crypto stream
                    stream = new CryptoStream(cipherData, transform, CryptoStreamMode.Read, leaveOpen: options.LeaveOpen);
                    // Prepend a compression stream
                    if (options.Compressed)
                    {
                        (options.Compression, _, long uncompressedLength) = await CompressionHelper.ReadOptionsAsync(stream, rawData, options.Compression, cancellationToken).DynamicContext();
                        options.Compression.LeaveOpen = false;
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
                throw new CryptographicException(ex.Message, ex);
            }
        }
    }
}
