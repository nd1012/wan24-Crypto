namespace wan24.Crypto
{
    /// <summary>
    /// Key types enumeration
    /// </summary>
    [Flags]
    public enum KeyTypes : byte
    {
        /// <summary>
        /// None
        /// </summary>
        None = 0,
        /// <summary>
        /// Symmetric key (byte sequence)
        /// </summary>
        Symmetric = 1,
        /// <summary>
        /// Asymmetric key
        /// </summary>
        Asymmetric = 2,
        /// <summary>
        /// Asymmetric private key (<see cref="IAsymmetricPrivateKey"/>)
        /// </summary>
        AsymmetricPrivate = Asymmetric | Private,
        /// <summary>
        /// Asymmetric public key (<see cref="IAsymmetricPublicKey"/>)
        /// </summary>
        AsymmetricPublic = Asymmetric | Public,
        /// <summary>
        /// Key suite
        /// </summary>
        Suite = 3,
        /// <summary>
        /// Private suite (<see cref="PrivateKeySuite"/>)
        /// </summary>
        PrivateSuite = Suite | Private,
        /// <summary>
        /// Public suite (<see cref="PublicKeySuite"/>)
        /// </summary>
        PublicSuite = Suite | Public,
        /// <summary>
        /// Private site store (<see cref="PrivateKeySuiteStore"/>)
        /// </summary>
        PrivateSuiteStore = Suite | Private | Store,
        /// <summary>
        /// Public suite store (<see cref="PublicKeySuiteStore"/>)
        /// </summary>
        PublicSuiteStore = Suite | Public | Store,
        /// <summary>
        /// PAKE record (<see cref="PakeRecord"/>)
        /// </summary>
        Pake = 4,
        /// <summary>
        /// PAKE record store (<see cref="PakeRecordStore"/>)
        /// </summary>
        PakeStore = Pake | Store,
        /// <summary>
        /// PKI (<see cref="SignedPkiStore"/>)
        /// </summary>
        Pki = 5 | Store,
        /// <summary>
        /// Crypto options (<see cref="CryptoOptions"/>)
        /// </summary>
        Options = 6,
        /// <summary>
        /// Key store
        /// </summary>
        Store = 32,
        /// <summary>
        /// Private key
        /// </summary>
        Private = 64,
        /// <summary>
        /// Public key
        /// </summary>
        Public = 128,
        /// <summary>
        /// All flags
        /// </summary>
        FLAGS = Private | Public
    }
}
