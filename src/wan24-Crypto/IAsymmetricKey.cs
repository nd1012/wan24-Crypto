﻿using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric key
    /// </summary>
    public interface IAsymmetricKey : IDisposableObject, IStreamSerializerVersion, IStatusProvider
    {
        /// <summary>
        /// Key ID
        /// </summary>
        byte[] ID { get; }
        /// <summary>
        /// Algorithm name
        /// </summary>
        IAsymmetricAlgorithm Algorithm { get; }
        /// <summary>
        /// Key size in bits
        /// </summary>
        int Bits { get; }
        /// <summary>
        /// Key data
        /// </summary>
        SecureByteArray KeyData { get; }
        /// <summary>
        /// Export the key data
        /// </summary>
        /// <returns>Key data</returns>
        byte[] Export();
    }
}
