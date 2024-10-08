﻿using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// AES-256-CBC symmetric encryption algorithm (using ISO10126 padding)
    /// </summary>
    public sealed record class EncryptionAes256CbcAlgorithm : EncryptionAlgorithmBase
    {
        /// <summary>
        /// Algorithm name
        /// </summary>
        public const string ALGORITHM_NAME = "AES256CBC";
        /// <summary>
        /// Algorithm value
        /// </summary>
        public const int ALGORITHM_VALUE = 0;
        /// <summary>
        /// Key size in bytes
        /// </summary>
        public const int KEY_SIZE = 32;
        /// <summary>
        /// IV size in bytes
        /// </summary>
        public const int IV_SIZE = 16;
        /// <summary>
        /// Block size in bytes
        /// </summary>
        public const int BLOCK_SIZE = 16;
        /// <summary>
        /// Maximum cipher data length in bytes
        /// </summary>
        public const long MAX_CIPHER_DATA_LENGTH = 140737488355328;
        /// <summary>
        /// Maximum key usage count
        /// </summary>
        public const long MAX_KEY_USAGE_COUNT = 65000000;
        /// <summary>
        /// Display name
        /// </summary>
        public const string DISPLAY_NAME = "AES-256-CBC";
        /// <summary>
        /// AES-256-CBC raw (without header) and uncompressed profile key
        /// </summary>
        public const string PROFILE_AES256CBC_RAW = "AES256CBC_RAW";

        /// <summary>
        /// Static constructor
        /// </summary>
        static EncryptionAes256CbcAlgorithm() => Instance = new();

        /// <summary>
        /// Constructor
        /// </summary>
        private EncryptionAes256CbcAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        /// <summary>
        /// Instance
        /// </summary>
        public static EncryptionAes256CbcAlgorithm Instance { get; }

        /// <inheritdoc/>
        public override int KeySize => KEY_SIZE;

        /// <inheritdoc/>
        public override int IvSize => IV_SIZE;

        /// <inheritdoc/>
        public override int BlockSize => BLOCK_SIZE;

        /// <inheritdoc/>
        public override bool RequireMacAuthentication => true;

        /// <inheritdoc/>
        public override bool IsPostQuantum => true;

        /// <inheritdoc/>
        public override bool IsSupported => !ENV.IsBrowserApp;

        /// <inheritdoc/>
        public override string DisplayName => DISPLAY_NAME;

        /// <inheritdoc/>
        public override long MaxCipherDataLength => MAX_CIPHER_DATA_LENGTH;

        /// <inheritdoc/>
        public override long MaxKeyUsageCount => MAX_KEY_USAGE_COUNT;

        /// <inheritdoc/>
        public override byte[] EnsureValidKeyLength(byte[] key) => GetValidLengthKey(key, KEY_SIZE);

        /// <inheritdoc/>
        public override bool IsKeyLengthValid(int len) => len == KEY_SIZE;

        /// <summary>
        /// Create the AES instance
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>AES instance</returns>
        public Aes CreateAes(CryptoOptions options)
        {
            try
            {
                byte[] pwd = options.Password?.CloneArray() ?? throw new ArgumentException("Missing password", nameof(options));
                Aes res = Aes.Create();
                try
                {
                    if (!IsKeyLengthValid(pwd.Length))
                    {
                        byte[] temp = EnsureValidKeyLength(pwd);
                        pwd.Clear();
                        pwd = temp;
                    }
                    res.KeySize = KEY_SIZE << 3;
                    res.Mode = CipherMode.CBC;
                    res.Padding = PaddingMode.ISO10126;
                    res.Key = pwd;
                    return res;
                }
                catch(Exception ex)
                {
                    res.Dispose();
                    throw CryptographicException.From(ex);
                }
                finally
                {
                    pwd.Clear();
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

        /// <inheritdoc/>
        protected override ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                EnsureAllowed();
                using Aes aes = CreateAes(options);
                aes.IV = CreateIvBytes();
                cipherData.Write(aes.IV);
                return aes.CreateEncryptor();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override async Task<ICryptoTransform> GetEncryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                EnsureAllowed();
                using Aes aes = CreateAes(options);
                aes.IV = CreateIvBytes();
                await cipherData.WriteAsync(aes.IV, cancellationToken).DynamicContext();
                return aes.CreateEncryptor();
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

        /// <inheritdoc/>
        protected override ICryptoTransform GetDecryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                using Aes aes = CreateAes(options);
                aes.IV = ReadFixedIvBytes(cipherData, options);
                return aes.CreateDecryptor();
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

        /// <inheritdoc/>
        protected override async Task<ICryptoTransform> GetDecryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                using Aes aes = CreateAes(options);
                aes.IV = await ReadFixedIvBytesAsync(cipherData, options, cancellationToken).DynamicContext();
                return aes.CreateDecryptor();
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
