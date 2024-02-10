using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="AsymmetricSignedPublicKeyTypes"/> extensions
    /// </summary>
    public static class AsymmetricSignedPublicKeyTypesExtensions
    {
        /// <summary>
        /// Is unknown?
        /// </summary>
        /// <param name="type">Type</param>
        /// <returns>If unknown</returns>
        public static bool IsUnknown(this AsymmetricSignedPublicKeyTypes type) => type == AsymmetricSignedPublicKeyTypes.Unknown;

        /// <summary>
        /// Is a root signature key?
        /// </summary>
        /// <param name="type">Type</param>
        /// <returns>If is a root signature key</returns>
        public static bool IsRoot(this AsymmetricSignedPublicKeyTypes type) => type.RemoveFlags() == AsymmetricSignedPublicKeyTypes.Root;

        /// <summary>
        /// Is an intermediate signature key?
        /// </summary>
        /// <param name="type">Type</param>
        /// <returns>If is an intermediate signature key</returns>
        public static bool IsIntermediate(this AsymmetricSignedPublicKeyTypes type) => type.RemoveFlags() == AsymmetricSignedPublicKeyTypes.Intermediate;

        /// <summary>
        /// Is an end key?
        /// </summary>
        /// <param name="type">Type</param>
        /// <returns>If is an end key</returns>
        public static bool IsEnd(this AsymmetricSignedPublicKeyTypes type) => type.RemoveFlags() == AsymmetricSignedPublicKeyTypes.End;

        /// <summary>
        /// Is revoked?
        /// </summary>
        /// <param name="type">Type</param>
        /// <returns>If revoked</returns>
        public static bool IsRevoked(this AsymmetricSignedPublicKeyTypes type) => type.ContainsAnyFlag(AsymmetricSignedPublicKeyTypes.Revoked);
    }
}
