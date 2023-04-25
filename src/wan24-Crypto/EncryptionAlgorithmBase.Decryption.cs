using wan24.Core;

namespace wan24.Crypto
{
    // Decryption methods
    public partial class EncryptionAlgorithmBase
    {
        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public virtual Stream Decrypt(Stream cipherData, Stream rawData, byte[] pwd, CryptoOptions? options = null)
        {
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
            options = ReadOptions(cipherData, rawData, pwd, options);
            try
            {
                using DecryptionStreams crypto = GetDecryptionStream(cipherData, rawData, options);
                crypto.CryptoStream.CopyTo(rawData);
                return rawData;
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
            }
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <returns>Raw data</returns>
        public Stream Decrypt(Stream cipherData, Stream rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null)
        {
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
            options ??= DefaultOptions;
            options = EncryptionHelper.GetDefaultOptions(options);
            options.SetKeys(key);
            options = ReadOptions(cipherData, rawData, pwd: null, options);
            try
            {
                return Decrypt(cipherData, rawData, options.Password!, options);
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
            }
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Raw data</returns>
        public virtual async Task DecryptAsync(Stream cipherData, Stream rawData, byte[] pwd, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
            options = await ReadOptionsAsync(cipherData, rawData, pwd, options, cancellationToken).DynamicContext();
            try
            {
                DecryptionStreams crypto = await GetDecryptionStreamAsync(cipherData, rawData, options, cancellationToken).DynamicContext();
                await using (crypto.DynamicContext())
                    await crypto.CryptoStream.CopyToAsync(rawData, cancellationToken).DynamicContext();
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
            }
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="key">Private key</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Raw data</returns>
        public async Task DecryptAsync(Stream cipherData, Stream rawData, IAsymmetricPrivateKey key, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
            options ??= DefaultOptions;
            options = EncryptionHelper.GetDefaultOptions(options);
            options.SetKeys(key);
            options = await ReadOptionsAsync(cipherData, rawData, pwd: null, options, cancellationToken).DynamicContext();
            try
            {
                await DecryptAsync(cipherData, rawData, options.Password!, options, cancellationToken).DynamicContext();
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
            }
        }
    }
}
