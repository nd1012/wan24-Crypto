using wan24.Core;

namespace wan24.Crypto
{
    // Encryption methods
    public partial record class EncryptionAlgorithmBase
    {
        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="macStream">MAC stream</param>
        /// <returns>Cipher data</returns>
        public virtual Stream Encrypt(Stream rawData, Stream cipherData, byte[] pwd, CryptoOptions? options = null, MacStreams? macStream = null)
        {
            options = options?.GetCopy() ?? DefaultOptions;
            try
            {
                options.SetNewPassword(pwd.CloneArray());
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Write the header
                if (!options.HeaderProcessed)
                {
                    options.Tracer?.WriteTrace("Writing crypto header");
                    if (macStream is not null) throw new ArgumentException("MAC stream unexpected", nameof(macStream));
                    (options, macStream) = WriteOptions(rawData, cipherData, pwd, options);
                }
                // Create the crypto stream
                using EncryptionStreams crypto = GetEncryptionStream(rawData, cipherData, macStream, options);
                rawData.CopyTo(crypto.CryptoStream);
                if (crypto.Mac is null) return cipherData;
                // Write the MAC
                crypto.CryptoStream.Dispose();
                crypto.Mac.Stream.Dispose();
                long pos = cipherData.Position;
                cipherData.Position = options.MacPosition;
                options.Mac = crypto.Mac.Transform!.Hash ?? throw new InvalidProgramException();
                if (options.UsingCounterMac) HybridAlgorithmHelper.ComputeMac(options);
                cipherData.Write(options.Mac);
                cipherData.Position = pos;
                return cipherData;
            }
            catch (CryptographicException)
            {
                macStream?.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                macStream?.Dispose();
                throw CryptographicException.From(ex);
            }
            finally
            {
                options.Clear();
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public Stream Encrypt(Stream rawData, Stream cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
        {
            options = options?.GetCopy() ?? DefaultOptions;
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                EncryptionHelper.GetDefaultOptions(options);
                options.SetKeys(key);
                (options, MacStreams? macStream) = WriteOptions(rawData, cipherData, pwd: null, options);
                try
                {
                    return Encrypt(rawData, cipherData, options.Password!, options, macStream);
                }
                finally
                {
                    macStream?.Dispose();
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
            finally
            {
                options.Clear();
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher data</returns>
        public Stream Encrypt(Stream rawData, Stream cipherData, CryptoOptions options)
        {
            options = options.GetCopy();
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                EncryptionHelper.GetDefaultOptions(options);
                if(options.Password is null && options.PrivateKey is null)
                {
                    options.Tracer?.WriteTrace("Using private key store");
                    if (options.PrivateKeysStore is null) throw new ArgumentException("Missing private keys store", nameof(options));
                    options.PrivateKeyRevision = options.PrivateKeysStore.LatestRevision;
                    options.ApplyPrivateKeySuite(options.PrivateKeysStore.LatestSuite);
                }
                (options, MacStreams? macStream) = WriteOptions(rawData, cipherData, pwd: null, options);
                try
                {
                    return Encrypt(rawData, cipherData, options.Password!, options, macStream);
                }
                finally
                {
                    macStream?.Dispose();
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
            finally
            {
                options.Clear();
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="macStream">MAC stream</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cipher data</returns>
        public virtual async Task EncryptAsync(
            Stream rawData,
            Stream cipherData,
            byte[] pwd,
            CryptoOptions? options = null,
            MacStreams? macStream = null,
            CancellationToken cancellationToken = default
            )
        {
            options = options?.GetCopy() ?? DefaultOptions;
            try
            {
                options.SetNewPassword(pwd.CloneArray());
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Write the header
                if (!options.HeaderProcessed)
                {
                    options.Tracer?.WriteTrace("Writing crypto header");
                    if (macStream is not null) throw new ArgumentException("MAC stream unexpected", nameof(macStream));
                    (options, macStream) = await WriteOptionsAsync(rawData, cipherData, pwd, options, cancellationToken).DynamicContext();
                }
                // Create the crypto stream
                EncryptionStreams crypto = await GetEncryptionStreamAsync(rawData, cipherData, macStream, options, cancellationToken).DynamicContext();
                await using (crypto.DynamicContext())
                {
                    await rawData.CopyToAsync(crypto.CryptoStream, cancellationToken).DynamicContext();
                    if (crypto.Mac is null) return;
                    // Write the MAC
                    await crypto.CryptoStream.DisposeAsync().DynamicContext();
                    crypto.Mac.Stream.Dispose();
                    long pos = cipherData.Position;
                    cipherData.Position = options.MacPosition;
                    options.Mac = crypto.Mac.Transform!.Hash ?? throw new InvalidProgramException();
                    if (options.UsingCounterMac) HybridAlgorithmHelper.ComputeMac(options);
                    await cipherData.WriteAsync(options.Mac, cancellationToken).DynamicContext();
                    cipherData.Position = pos;
                }
            }
            catch (CryptographicException)
            {
                macStream?.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                macStream?.Dispose();
                throw await CryptographicException.FromAsync(ex);
            }
            finally
            {
                options.Clear();
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cipher data</returns>
        public async Task EncryptAsync(Stream rawData, Stream cipherData, IAsymmetricPrivateKey key, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            options = options?.GetCopy() ?? DefaultOptions;
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                EncryptionHelper.GetDefaultOptions(options);
                options.SetKeys(key);
                (options, MacStreams? macStream) = await WriteOptionsAsync(rawData, cipherData, pwd: null, options, cancellationToken).DynamicContext();
                try
                {
                    await EncryptAsync(rawData, cipherData, options.Password!, options, macStream, cancellationToken).DynamicContext();
                }
                finally
                {
                    macStream?.Dispose();
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
            finally
            {
                options.Clear();
            }
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cipher data</returns>
        public async Task EncryptAsync(Stream rawData, Stream cipherData, CryptoOptions options, CancellationToken cancellationToken = default)
        {
            options = options.GetCopy();
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                EncryptionHelper.GetDefaultOptions(options);
                if (options.Password is null && options.PrivateKey is null)
                {
                    options.Tracer?.WriteTrace("Using private key store");
                    if (options.PrivateKeysStore is null) throw new ArgumentException("Missing private keys store", nameof(options));
                    options.PrivateKeyRevision = options.PrivateKeysStore.LatestRevision;
                    options.ApplyPrivateKeySuite(options.PrivateKeysStore.LatestSuite);
                }
                (options, MacStreams? macStream) = await WriteOptionsAsync(rawData, cipherData, pwd: null, options, cancellationToken).DynamicContext();
                try
                {
                    await EncryptAsync(rawData, cipherData, options.Password!, options, macStream, cancellationToken).DynamicContext();
                }
                finally
                {
                    macStream?.Dispose();
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
            finally
            {
                options.Clear();
            }
        }
    }
}
