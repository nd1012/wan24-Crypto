using System.Reflection;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Object encryption helper
    /// </summary>
    public static class ObjectEncryption
    {
        /// <summary>
        /// Encrypt raw property values (<see cref="EncryptAttribute"/>) and optional the data encryption key (DEK; <see cref="DekAttribute"/>) property value
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pwd">Key encryption key (KEK; required when there's a DEK property)</param>
        /// <param name="dekLength">Generated DEK length in bytes</param>
        /// <param name="dataEncryptionKey">DEK to use (no DEK property required)</param>
        /// <param name="options">Options</param>
        /// <returns>Object</returns>
        public static T EncryptProperties<T>(in T obj, in byte[]? pwd = null, in int dekLength = 64, in byte[]? dataEncryptionKey = null, in CryptoOptions? options = null)
            where T : notnull
        {
            if (dekLength < 1) throw new ArgumentOutOfRangeException(nameof(dekLength));
            SecureByteArrayRefStruct dek = default;
            try
            {
                if (dataEncryptionKey is null)
                {
                    if (pwd is null) throw new ArgumentNullException(nameof(pwd));
                    PropertyInfoExt dekPi = obj.GetType().GetPropertiesCached(BindingFlags.Instance | BindingFlags.Public)
                        .FirstOrDefault(pi => pi.GetCustomAttributeCached<DekAttribute>() is not null) ??
                        throw new InvalidProgramException("DEK property not found");
                    if (dekPi.Getter is null) throw new InvalidProgramException("DEK has no getter");
                    if (dekPi.Setter is null) throw new InvalidProgramException("DEK has no setter");
                    DekAttribute dekAttr = dekPi.GetCustomAttributeCached<DekAttribute>() ?? throw new InvalidProgramException();
                    dekAttr.GetValue(obj, dekPi)?.Clear();
                    dek = new(RND.GetBytes(dekLength));
                    dekAttr.SetValue(obj, dekPi, dek.Array.Encrypt(pwd, options));
                }
                else
                {
                    dek = new(dataEncryptionKey.CloneArray());
                }
                byte[]? raw;
                EncryptAttribute attr;
                foreach (PropertyInfoExt pi in from pi in obj.GetType().GetPropertiesCached(BindingFlags.Instance | BindingFlags.Public)
                                               where pi.GetCustomAttributeCached<EncryptAttribute>() is not null
                                               select pi)
                {
                    if (pi.Getter is null) throw new InvalidProgramException($"Property {obj.GetType()}.{pi.Name} has no getter");
                    if (pi.Setter is null) throw new InvalidProgramException($"Property {obj.GetType()}.{pi.Name} has no setter");
                    attr = pi.GetCustomAttributeCached<EncryptAttribute>() ?? throw new InvalidProgramException();
                    raw = attr.GetRaw(obj, pi);
                    if (raw is null) continue;
                    try
                    {
                        attr.SetCipher(obj, pi, raw.Encrypt(dek.Array, options));
                    }
                    finally
                    {
                        raw.Clear();
                    }
                }
                return obj;
            }
            finally
            {
                dek.Dispose();
            }
        }

        /// <summary>
        /// Decrypt raw property values (<see cref="EncryptAttribute"/>) optional using the data encryption key (DEK; <see cref="DekAttribute"/>) property value
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pwd">Key encryption key (KEK; required when there's a DEK property)</param>
        /// <param name="dataEncryptionKey">DEK to use (no DEK property required)</param>
        /// <param name="options">Options</param>
        /// <returns>Object</returns>
        public static T DecryptProperties<T>(in T obj, in byte[]? pwd = null, in byte[]? dataEncryptionKey = null, in CryptoOptions? options = null) where T : notnull
        {
            byte[] dek;
            if (dataEncryptionKey is null)
            {
                if (pwd is null) throw new ArgumentNullException(nameof(pwd));
                PropertyInfoExt dekPi = obj.GetType().GetPropertiesCached(BindingFlags.Instance | BindingFlags.Public)
                    .FirstOrDefault(pi => pi.GetCustomAttributeCached<DekAttribute>() is not null) ??
                    throw new InvalidProgramException("DEK property not found");
                if (dekPi.Getter is null) throw new InvalidProgramException("DEK has no getter");
                DekAttribute dekAttr = dekPi.GetCustomAttributeCached<DekAttribute>() ?? throw new InvalidProgramException();
                dek = dekAttr.GetValue(obj, dekPi)?.Decrypt(pwd, options) ?? throw new InvalidDataException("No DEK found");
            }
            else
            {
                dek = dataEncryptionKey;
            }
            byte[]? cipher;
            EncryptAttribute attr;
            foreach (PropertyInfoExt pi in from pi in obj.GetType().GetPropertiesCached(BindingFlags.Instance | BindingFlags.Public)
                                            where pi.GetCustomAttributeCached<EncryptAttribute>() is not null
                                            select pi)
            {
                if (pi.Getter is null) throw new InvalidProgramException($"Property {obj.GetType()}.{pi.Name} has no getter");
                if (pi.Setter is null) throw new InvalidProgramException($"Property {obj.GetType()}.{pi.Name} has no setter");
                attr = pi.GetCustomAttributeCached<EncryptAttribute>() ?? throw new InvalidProgramException();
                cipher = attr.GetCipher(obj, pi);
                if (cipher is null) continue;
                attr.SetRaw(obj, pi, cipher.Decrypt(dek, options));
            }
            return obj;
        }

        /// <summary>
        /// Encrypt raw property values (<see cref="EncryptAttribute"/>) and optional the data encryption key (DEK; <see cref="DekAttribute"/>) property value
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pwd">Key encryption key (KEK; required when there's a DEK property)</param>
        /// <param name="dekLength">Generated DEK length in bytes</param>
        /// <param name="dataEncryptionKey">DEK to use (no DEK property required)</param>
        /// <param name="options">Options</param>
        /// <returns>Object</returns>
        public static T EncryptObject<T>(this T obj, in byte[]? pwd = null, in int dekLength = 64, in byte[]? dataEncryptionKey = null, in CryptoOptions? options = null)
            where T : IEncryptProperties
        {
            IEncryptPropertiesExt? ext = obj as IEncryptPropertiesExt;
            ext?.BeforeEncrypt(pwd, dekLength, dataEncryptionKey, options);
            EncryptProperties(obj, pwd, dekLength, dataEncryptionKey, options);
            ext?.AfterEncrypt(pwd, dekLength, dataEncryptionKey, options);
            return obj;
        }

        /// <summary>
        /// Decrypt raw property values (<see cref="EncryptAttribute"/>) optional using the data encryption key (DEK; <see cref="DekAttribute"/>) property value
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pwd">Key encryption key (KEK; required when there's a DEK property)</param>
        /// <param name="dataEncryptionKey">DEK to use (no DEK property required)</param>
        /// <param name="options">Options</param>
        /// <returns>Object</returns>
        public static T DecryptObject<T>(this T obj, in byte[]? pwd = null, in byte[]? dataEncryptionKey = null, in CryptoOptions? options = null)
            where T : IEncryptProperties
        {
            IEncryptPropertiesExt? ext = obj as IEncryptPropertiesExt;
            ext?.BeforeDecrypt(pwd, dataEncryptionKey, options);
            DecryptProperties(obj, pwd, dataEncryptionKey, options);
            ext?.AfterDecrypt(pwd, dataEncryptionKey, options);
            return obj;
        }

        /// <summary>
        /// Get the data encryption key (DEK) of an object (won't be decrypted!)
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <returns>DEK</returns>
        public static byte[]? GetDek<T>(this T obj) where T : IEncryptProperties
        {
            PropertyInfoExt dekPi = obj.GetType().GetPropertiesCached(BindingFlags.Instance | BindingFlags.Public)
                .FirstOrDefault(pi => pi.GetCustomAttributeCached<DekAttribute>() is not null) ??
                throw new InvalidProgramException("DEK property not found");
            if (dekPi.Getter is null) throw new InvalidProgramException("DEK has no getter");
            return dekPi.Getter(obj) as byte[];
        }

        /// <summary>
        /// Get the data encryption key (DEK) of an object
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <param name="pwd">Key encryption key (KEK)</param>
        /// <param name="options">Options</param>
        /// <returns>DEK</returns>
        public static byte[]? GetDek<T>(this T obj, in byte[] pwd, in CryptoOptions? options = null) where T : IEncryptProperties => GetDek(obj)?.Decrypt(pwd, options);

        /// <summary>
        /// Determine if a DEK property is available
        /// </summary>
        /// <typeparam name="T">Object type</typeparam>
        /// <param name="obj">Object</param>
        /// <returns>If a DEK property is available</returns>
        public static bool HasDek<T>(this T obj) where T : IEncryptProperties => obj.GetType().GetPropertiesCached(BindingFlags.Instance | BindingFlags.Public)
                .Any(pi => pi.GetCustomAttributeCached<DekAttribute>() is not null);
    }
}
