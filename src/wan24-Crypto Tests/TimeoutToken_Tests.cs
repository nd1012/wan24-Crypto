using System.Runtime.InteropServices;
using System.Security.Cryptography;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class TimeoutToken_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            TimeSpan timeout = TimeSpan.FromMilliseconds(100);
            ulong payload = 123;
            byte[] pwd = RandomNumberGenerator.GetBytes(20);
            TimeoutToken tt = new(DateTime.UtcNow, timeout, payload, pwd);
            Assert.IsFalse(tt.IsTimeout);
            Assert.IsTrue(tt.Timeleft > TimeSpan.Zero);
            Assert.AreEqual(TimeoutToken.STRUCT_LENGTH, Marshal.SizeOf(tt));
            Assert.AreEqual(payload, tt.Payload);
            Assert.IsTrue(tt.ValidateToken(pwd, throwOnError: false));
            Assert.IsFalse(tt.ValidateToken(RandomNumberGenerator.GetBytes(20), throwOnError: false));
            long ticks = tt.Timeout.Ticks;
            byte[] serialized = tt;
            Thread.Sleep(100);
            tt = (TimeoutToken)serialized;
            Assert.IsTrue(tt.IsTimeout);
            Assert.AreEqual(TimeSpan.Zero, tt.Timeleft);
            Assert.AreEqual(ticks, tt.Timeout.Ticks);
            Assert.AreEqual(payload, tt.Payload);
            Assert.IsTrue(tt.ValidateToken(pwd, throwOnError: false));
            Assert.IsFalse(tt.ValidateToken(RandomNumberGenerator.GetBytes(20), throwOnError: false));
        }

        [TestMethod]
        public void Marshal_Tests()
        {
            TimeSpan timeout = TimeSpan.FromMilliseconds(100);
            ulong payload = 123;
            byte[] pwd = RandomNumberGenerator.GetBytes(20);
            TimeoutToken tt = new(DateTime.UtcNow, timeout, payload, pwd);
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(tt));
            try
            {
                Marshal.StructureToPtr(tt, ptr, fDeleteOld: false);
                tt = Marshal.PtrToStructure<TimeoutToken>(ptr);
                Assert.IsFalse(tt.IsTimeout);
                Assert.IsTrue(tt.Timeleft > TimeSpan.Zero);
                Assert.AreEqual(TimeoutToken.STRUCT_LENGTH, Marshal.SizeOf(tt));
                Assert.AreEqual(payload, tt.Payload);
                Assert.IsTrue(tt.ValidateToken(pwd, throwOnError: false));
                Assert.IsFalse(tt.ValidateToken(RandomNumberGenerator.GetBytes(20), throwOnError: false));
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}
