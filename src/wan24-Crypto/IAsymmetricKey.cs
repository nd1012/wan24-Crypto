﻿using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Interface for an asymmetric key
    /// </summary>
    public interface IAsymmetricKey : IDisposableObject, IStreamSerializerVersion
    {
        /// <summary>
        /// Key ID
        /// </summary>
        byte[] ID { get; }
        /// <summary>
        /// Algorithm name
        /// </summary>
        string Algorithm { get; }
        /// <summary>
        /// Bits
        /// </summary>
        int Bits { get; }
        /// <summary>
        /// Key data
        /// </summary>
        SecureByteArray KeyData { get; }
    }
}
