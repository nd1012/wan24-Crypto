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
            CryptoOptions? givenOptions = options;
            try
            {
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                options = ReadOptions(cipherData, rawData, pwd, options);
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
                throw CryptographicException.From(ex);
            }
            finally
            {
                if (options != givenOptions) options!.Clear();
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
            options = options?.Clone() ?? DefaultOptions;
            try
            {
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                options.SetKeys(key);
                options = ReadOptions(cipherData, rawData, pwd: null, options);
                return Decrypt(cipherData, rawData, options.Password!, options);
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
            CryptoOptions? givenOptions = options;
            try
            {
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                options = await ReadOptionsAsync(cipherData, rawData, pwd, options, cancellationToken).DynamicContext();
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
                throw await CryptographicException.FromAsync(ex);
            }
            finally
            {
                if (options != givenOptions) options!.Clear();
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
            options = options?.Clone() ?? DefaultOptions;
            try
            {
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                options.SetKeys(key);
                options = await ReadOptionsAsync(cipherData, rawData, pwd: null, options, cancellationToken).DynamicContext();
                await DecryptAsync(cipherData, rawData, options.Password!, options, cancellationToken).DynamicContext();
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
