using wan24.Core;

namespace wan24.Crypto
{
    // Encryption methods
    public partial class EncryptionAlgorithmBase
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
            bool clearOptions = false;
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Write the header
                if (!(options?.HeaderProcessed ?? false))
                {
                    if (macStream is not null) throw new ArgumentException("MAC stream unexpected", nameof(macStream));
                    (options, macStream) = WriteOptions(rawData, cipherData, pwd, options);
                    clearOptions = true;
                }
                // Create the crypto stream
                using EncryptionStreams crypto = GetEncryptionStream(rawData, cipherData, macStream, options);
                rawData.CopyTo(crypto.CryptoStream);
                if (crypto.Mac is null) return cipherData;
                // Write the MAC
                crypto.CryptoStream.Dispose();
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
                if (clearOptions) options?.Clear();
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
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                options ??= DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                options.SetKeys(key);
                (options, MacStreams? macStream) = WriteOptions(rawData, cipherData, pwd: null, options);
                try
                {
                    return Encrypt(rawData, cipherData, options.Password!, options, macStream);
                }
                finally
                {
                    options.Clear();
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
            bool clearOptions = false;
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Write the header
                if (!(options?.HeaderProcessed ?? false))
                {
                    if (macStream is not null) throw new ArgumentException("MAC stream unexpected", nameof(macStream));
                    (options, macStream) = await WriteOptionsAsync(rawData, cipherData, pwd, options, cancellationToken).DynamicContext();
                    clearOptions = true;
                }
                // Create the crypto stream
                EncryptionStreams crypto = await GetEncryptionStreamAsync(rawData, cipherData, macStream, options, cancellationToken).DynamicContext();
                await using (crypto.DynamicContext())
                {
                    await rawData.CopyToAsync(crypto.CryptoStream, cancellationToken).DynamicContext();
                    if (crypto.Mac is null) return;
                    // Write the MAC
                    await crypto.CryptoStream.DisposeAsync().DynamicContext();
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
                if (clearOptions) options?.Clear();
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
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                options ??= DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                options.SetKeys(key);
                (options, MacStreams? macStream) = await WriteOptionsAsync(rawData, cipherData, pwd: null, options, cancellationToken).DynamicContext();
                try
                {
                    await EncryptAsync(rawData, cipherData, options.Password!, options, macStream, cancellationToken).DynamicContext();
                }
                finally
                {
                    options.Clear();
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
        }
    }
}
