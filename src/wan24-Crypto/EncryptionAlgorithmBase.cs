﻿using System.Security.Cryptography;
using wan24.Compression;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Base class for a symmetric encryption algorithm
    /// </summary>
    public abstract partial class EncryptionAlgorithmBase : CryptoAlgorithmBase
    {
        /// <summary>
        /// Default options
        /// </summary>
        protected CryptoOptions _DefaultOptions;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <param name="value">Algorithm value</param>
        protected EncryptionAlgorithmBase(string name, int value) : base(name, value)
            => _DefaultOptions = new()
            {
                Compression = CompressionHelper.GetDefaultOptions(),
                Algorithm = name,
                MacAlgorithm = MacHelper.DefaultAlgorithm.Name,
                KdfAlgorithm = KdfHelper.DefaultAlgorithm.Name,
                KdfIterations = KdfHelper.DefaultAlgorithm.DefaultIterations
            };

        /// <summary>
        /// Default options
        /// </summary>
        public CryptoOptions DefaultOptions => _DefaultOptions.Clone();

        /// <summary>
        /// Create random IV bytes
        /// </summary>
        /// <returns>IV bytes</returns>
        protected virtual byte[] CreateIvBytes() => RandomNumberGenerator.GetBytes(IvSize);

        /// <summary>
        /// Read the fixed IV bytes
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <returns>IV bytes</returns>
        protected virtual byte[] ReadFixedIvBytes(Stream cipherData, CryptoOptions options)
        {
            byte[] res = new byte[IvSize];
            if (cipherData.Read(res) != IvSize) throw new CryptographicException($"Failed to read {IvSize} IV bytes");
            return res;
        }

        /// <summary>
        /// Read the fixed IV bytes
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>IV bytes</returns>
        protected virtual async Task<byte[]> ReadFixedIvBytesAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            byte[] res = new byte[IvSize];
            if (await cipherData.ReadAsync(res, cancellationToken).DynamicContext() != IvSize) throw new CryptographicException($"Failed to read {IvSize} IV bytes");
            return res;
        }

        /// <summary>
        /// Read the variable IV bytes
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <returns>IV bytes</returns>
        protected virtual byte[] ReadVariableIvBytes(Stream cipherData, CryptoOptions options)
        {
            try
            {
                return cipherData.ReadBytes(options.SerializerVersion, minLen: IvSize, maxLen: byte.MaxValue).Value;
            }
            catch(Exception ex)
            {
                throw new CryptographicException($"Failed to read IV bytes: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Read the variable IV bytes
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>IV bytes</returns>
        protected virtual async Task<byte[]> ReadVariableIvBytesAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                return (await cipherData.ReadBytesAsync(options.SerializerVersion, minLen: IvSize, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            }
            catch (Exception ex)
            {
                throw new CryptographicException($"Failed to read IV bytes: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Encode flags
        /// </summary>
        /// <param name="flags">Flags</param>
        /// <param name="buffer">Buffer</param>
        protected virtual void EncodeFlags(CryptoFlags flags, byte[] buffer)
        {
            int f = (int)flags;
            buffer[0] = (byte)f;
            buffer[1] = (byte)(f >> 8);
            buffer[2] = (byte)(f >> 16);
        }

        /// <summary>
        /// Decode flags
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <returns>Flags</returns>
        protected virtual CryptoFlags DecodeFlags(byte[] buffer)
        {
            int res = buffer[0];
            res |= buffer[1] << 8;
            res |= buffer[2] << 16;
            return (CryptoFlags)res;
        }
    }
}
