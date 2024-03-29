﻿using System.Security.Cryptography;

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
        /// An object for static thread locking
        /// </summary>
        private static object SyncObject = new();
        /// <summary>
        /// Denied curve key sizes in bits
        /// </summary>
        private static readonly HashSet<int> DeniedCurves = [];
        /// <summary>
        /// secp256r1 curve (NIST P-256, 128 bit security)
        /// </summary>
        public static readonly ECCurve SECP256R1_CURVE = ECCurve.NamedCurves.nistP256;
        /// <summary>
        /// secp384r1 curve (NIST P-384, 192 bit security)
        /// </summary>
        public static readonly ECCurve SECP384R1_CURVE = ECCurve.NamedCurves.nistP384;
        /// <summary>
        /// secp521r1 curve (NIST P-521, 260 bit security)
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
            if (curve.Oid.Value is string oid)
                if (oid == SECP256R1_CURVE.Oid.Value) return GetKeySize(SECP256R1);
                else if (oid == SECP384R1_CURVE.Oid.Value) return GetKeySize(SECP384R1);
                else if (oid == SECP521R1_CURVE.Oid.Value) return GetKeySize(SECP521R1);
            if (curve.Oid.FriendlyName is string name)
                if (name == SECP256R1_CURVE.Oid.FriendlyName) return GetKeySize(SECP256R1);
                else if (name == SECP384R1_CURVE.Oid.FriendlyName) return GetKeySize(SECP384R1);
                else if (name == SECP521R1_CURVE.Oid.FriendlyName) return GetKeySize(SECP521R1);
            throw new ArgumentException($"Unknown curve \"{curve.Oid.FriendlyName}\" (OID {curve.Oid.Value})", nameof(curve));
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

        /// <summary>
        /// Determine if an elliptic curve is allowed
        /// </summary>
        /// <param name="curve">Curve</param>
        /// <returns>If the elliptic curve is allowed</returns>
        public static bool IsCurveAllowed(in ECCurve curve) => IsCurveAllowed(GetKeySize(curve));

        /// <summary>
        /// Determine if an elliptic curve is allowed
        /// </summary>
        /// <param name="name">Curve name</param>
        /// <returns>If the elliptic curve is allowed</returns>
        public static bool IsCurveAllowed(in string name) => IsCurveAllowed(GetKeySize(name));

        /// <summary>
        /// Determine if an elliptic curve is allowed
        /// </summary>
        /// <param name="bits">Key size in bits</param>
        /// <returns>If the elliptic curve is allowed</returns>
        public static bool IsCurveAllowed(in int bits)
        {
            lock (SyncObject) return !DeniedCurves.Contains(bits);
        }

        /// <summary>
        /// Deny an elliptic curve
        /// </summary>
        /// <param name="curve">Curve</param>
        public static void DenyCurve(in ECCurve curve) => DenyCurve(GetKeySize(curve));

        /// <summary>
        /// Deny an elliptic curve
        /// </summary>
        /// <param name="name">Curve name</param>
        public static void DenyCurve(in string name) => DenyCurve(GetKeySize(name));

        /// <summary>
        /// Deny an elliptic curve
        /// </summary>
        /// <param name="bits">Key size in bits</param>
        public static void DenyCurve(in int bits)
        {
            lock (SyncObject) DeniedCurves.Add(bits);
        }
    }
}
