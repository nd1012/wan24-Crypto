using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// Elliptic curves
    /// </summary>
    public static class EllipticCurves
    {
        /// <summary>
        /// secp256r1
        /// </summary>
        public const string SECP256R1 = "secp256r1";
        /// <summary>
        /// secp384r1
        /// </summary>
        public const string SECP384R1 = "secp384r1";
        /// <summary>
        /// secp521r1
        /// </summary>
        public const string SECP521R1 = "secp521r1";
        /// <summary>
        /// secp256r1 key size in bits
        /// </summary>
        public const int SECP256R1_KEY_SIZE = 256;
        /// <summary>
        /// secp384r1 key size in bits
        /// </summary>
        public const int SECP384R1_KEY_SIZE = 384;
        /// <summary>
        /// secp521r1 key size in bits
        /// </summary>
        public const int SECP521R1_KEY_SIZE = 521;
        /// <summary>
        /// Default curve name (secp521r1)
        /// </summary>
        public const string DEFAULT_NAME = SECP521R1;
        /// <summary>
        /// Default key size in bits (521)
        /// </summary>
        public const int DEFAULT_KEY_SIZE = 521;

        /// <summary>
        /// secp256r1 curve
        /// </summary>
        public static readonly ECCurve SECP256R1_CURVE = ECCurve.NamedCurves.nistP256;
        /// <summary>
        /// secp384r1 curve
        /// </summary>
        public static readonly ECCurve SECP384R1_CURVE = ECCurve.NamedCurves.nistP384;
        /// <summary>
        /// secp521r1 curve
        /// </summary>
        public static readonly ECCurve SECP521R1_CURVE = ECCurve.NamedCurves.nistP521;

        /// <summary>
        /// Get the key size for a curve
        /// </summary>
        /// <param name="curve">Curve name</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(string curve) => curve switch
        {
            SECP256R1 => SECP256R1_KEY_SIZE,
            SECP384R1 => SECP384R1_KEY_SIZE,
            SECP521R1 => SECP521R1_KEY_SIZE,
            _ => throw new ArgumentException("Unknown curve", nameof(curve))
        };

        /// <summary>
        /// Get the key size for a curve
        /// </summary>
        /// <param name="curve">Curve</param>
        /// <returns>Key size in bits</returns>
        public static int GetKeySize(ECCurve curve)
        {
            string name = curve.Oid.FriendlyName ?? curve.Oid.Value ?? throw new ArgumentException("Unknown curve", nameof(curve));
            if (name == SECP256R1_CURVE.Oid.FriendlyName || name == SECP256R1_CURVE.Oid.Value) name = SECP256R1;
            else if (name == SECP384R1_CURVE.Oid.FriendlyName || name == SECP384R1_CURVE.Oid.Value) name = SECP384R1;
            else if (name == SECP521R1_CURVE.Oid.FriendlyName || name == SECP521R1_CURVE.Oid.Value) name = SECP521R1;
            else throw new ArgumentException("Unknown curve", nameof(curve));
            return GetKeySize(name);
        }

        /// <summary>
        /// Get the curve name from a key size
        /// </summary>
        /// <param name="bits">Key size in bits</param>
        /// <returns>Curve name</returns>
        public static string GetCurveName(int bits) => bits switch
        {
            SECP256R1_KEY_SIZE => SECP256R1,
            SECP384R1_KEY_SIZE => SECP384R1,
            SECP521R1_KEY_SIZE => SECP521R1,
            _ => throw new ArgumentException("Unknown key size", nameof(bits))
        };

        /// <summary>
        /// Get the curve from a key size
        /// </summary>
        /// <param name="bits">Key size in bits</param>
        /// <returns>Curve name</returns>
        public static ECCurve GetCurve(int bits) => bits switch
        {
            SECP256R1_KEY_SIZE => SECP256R1_CURVE,
            SECP384R1_KEY_SIZE => SECP384R1_CURVE,
            SECP521R1_KEY_SIZE => SECP521R1_CURVE,
            _ => throw new ArgumentException("Unknown key size", nameof(bits))
        };
    }
}
