using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE extensions
    /// </summary>
    public static class PakeExtensions
    {
        /// <summary>
        /// Get XOR bytes of a PAKE record
        /// </summary>
        /// <param name="record">Record</param>
        /// <param name="request">Any PAKE request</param>
        /// <returns>Bytes (only the secret must be stored separately in addition)</returns>
        public static byte[] GetXorBytes(this IPakeRecord record, in IPakeRequest request)
        {
            byte[] res = new byte[record.Identifier.Length];
            GetXorBytes(record, request, res.AsSpan());
            return res;
        }

        /// <summary>
        /// Get XOR bytes of a PAKE record
        /// </summary>
        /// <param name="record">Record</param>
        /// <param name="request">Any PAKE request</param>
        /// <param name="output">Output (length needs to fit the record values length)</param>
        /// <returns>Output (only the secret must be stored separately in addition)</returns>
        public static Span<byte> GetXorBytes(this IPakeRecord record, in IPakeRequest request, in Span<byte> output)
        {
            if (output.Length != record.Identifier.Length) throw new ArgumentOutOfRangeException(nameof(output));
            output.Xor(record.Identifier);
            output.Xor(record.SignatureKey);
            output.Xor(request.Key);
            return output;
        }

        /// <summary>
        /// Get a PAKE record off PAKE record XOR bytes using a PAKE request
        /// </summary>
        /// <param name="request">Request</param>
        /// <param name="pakeRecordXorBytes">XOR bytes</param>
        /// <param name="pakeRecordSecret">PAKE record secret</param>
        /// <returns>PAKE record (don't forget to dispose!)</returns>
        public static IPakeRecord GetRecord(this IPakeRequest request, in ReadOnlySpan<byte> pakeRecordXorBytes, in ReadOnlySpan<byte> pakeRecordSecret)
        {
            if (request.Identifier.Length != pakeRecordXorBytes.Length) throw new ArgumentOutOfRangeException(nameof(pakeRecordXorBytes));
            using RentedArrayRefStruct<byte> buffer = new(len: pakeRecordXorBytes.Length, clean: false)
            {
                Clear = true
            };
            Span<byte> bufferSpan = buffer.Span;
            pakeRecordXorBytes.CopyTo(bufferSpan);
            bufferSpan.Xor(request.Identifier);
            bufferSpan.Xor(request.Key);
            return new PakeRecord(request.Identifier, pakeRecordSecret.ToArray(), bufferSpan.ToArray());
        }

        /// <summary>
        /// Get a MAC of the identifier
        /// </summary>
        /// <param name="request">Request</param>
        /// <param name="options">Options</param>
        /// <returns>Identifier MAC</returns>
        public static byte[] GetIdentifierMac(this IPakeRequest request, in CryptoOptions? options = null) => request.Identifier.Mac(request.Key, options);

        /// <summary>
        /// Get a MAC of the identifier
        /// </summary>
        /// <param name="request">Request</param>
        /// <param name="mac">MAC output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>Identifier MAC</returns>
        public static Span<byte> GetIdentifierMac(this IPakeRequest request, in Span<byte> mac, in CryptoOptions? options = null)
            => request.Identifier.AsSpan().Mac(request.Key, mac, options);

        /// <summary>
        /// Validate an identifier MAC
        /// </summary>
        /// <param name="request">Request</param>
        /// <param name="identifierMac">Identifier MAC</param>
        /// <param name="options">Options</param>
        /// <param name="throwOnError">Throw an exception on error?</param>
        /// <returns>If the identifier MAC is valid</returns>
        public static bool ValidateIdentifierMac(this IPakeRequest request, in ReadOnlySpan<byte> identifierMac, CryptoOptions? options = null, in bool throwOnError = true)
        {
            options = MacHelper.GetDefaultOptions(options);
            using RentedArrayRefStruct<byte> buffer = new(len: MacHelper.GetAlgorithm(options.MacAlgorithm!).MacLength, clean: false)
            {
                Clear = true
            };
            if (identifierMac.SlowCompare(GetIdentifierMac(request, buffer.Span, options))) return true;
            if (!throwOnError) return false;
            throw CryptographicException.From("Identifier MAC mismatch", new InvalidDataException());
        }
    }
}
