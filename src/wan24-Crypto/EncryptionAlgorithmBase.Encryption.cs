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
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Write the header
                if (!(options?.HeaderProcessed ?? false))
                {
                    if (macStream != null) throw new ArgumentException("MAC stream unexpected", nameof(macStream));
                    (options, macStream) = WriteOptions(rawData, cipherData, pwd, options);
                    clearOptions = true;
                }
                // Create the crypto stream
                using EncryptionStreams crypto = GetEncryptionStream(rawData, cipherData, macStream, options);
                rawData.CopyTo(crypto.CryptoStream);
                if (crypto.Mac == null) return cipherData;
                // Write the MAC
                crypto.CryptoStream.Dispose();
                long pos = cipherData.Position;
                cipherData.Position = options.MacPosition;
                byte[] mac = crypto.Mac.Transform!.Hash ?? throw new InvalidProgramException();
                if (options.UsingCounterMac) mac = HybridAlgorithmHelper.ComputeMac(mac, options);
                cipherData.Write(mac);
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
                throw new CryptographicException(ex.Message, ex);
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
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
            options ??= DefaultOptions;
            options.SetPrivateKey(key);
            (options, MacStreams? macStream) = WriteOptions(rawData, cipherData, pwd: null, options);
            try
            {
                return Encrypt(rawData, cipherData, options.Password!, options, macStream);
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
            }
            finally
            {
                options.Clear();
                macStream?.Dispose();
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
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Write the header
                if (!(options?.HeaderProcessed ?? false))
                {
                    if (macStream != null) throw new ArgumentException("MAC stream unexpected", nameof(macStream));
                    (options, macStream) = await WriteOptionsAsync(rawData, cipherData, pwd, options, cancellationToken).DynamicContext();
                    clearOptions = true;
                }
                // Create the crypto stream
                EncryptionStreams crypto = await GetEncryptionStreamAsync(rawData, cipherData, macStream, options, cancellationToken).DynamicContext();
                await using (crypto.DynamicContext())
                {
                    await rawData.CopyToAsync(crypto.CryptoStream, cancellationToken).DynamicContext();
                    if (crypto.Mac == null) return;
                    // Write the MAC
                    await crypto.CryptoStream.DisposeAsync().DynamicContext();
                    long pos = cipherData.Position;
                    cipherData.Position = options.MacPosition;
                    byte[] mac = crypto.Mac.Transform!.Hash ?? throw new InvalidProgramException();
                    if (options.UsingCounterMac) mac = HybridAlgorithmHelper.ComputeMac(mac, options);
                    await cipherData.WriteAsync(mac, cancellationToken).DynamicContext();
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
                throw new CryptographicException(ex.Message, ex);
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
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
            options ??= DefaultOptions;
            options.SetPrivateKey(key);
            (options, MacStreams? macStream) = await WriteOptionsAsync(rawData, cipherData, pwd: null, options, cancellationToken).DynamicContext();
            try
            {
                await EncryptAsync(rawData, cipherData, options.Password!, options, macStream, cancellationToken).DynamicContext();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new CryptographicException(ex.Message, ex);
            }
            finally
            {
                options.Clear();
                macStream?.Dispose();
            }
        }
    }
}
