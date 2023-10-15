﻿using Microsoft.Extensions.Logging;
using wan24.Core;
using wan24.ObjectValidation;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class A_Initialization
    {
        public static ILoggerFactory LoggerFactory { get; private set; } = null!;

        [AssemblyInitialize]
        public static void Init(TestContext tc)
        {
            LoggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(b => b.AddConsole());
            Logging.Logger = LoggerFactory.CreateLogger("Tests");
            ValidateObject.Logger = (message) => Logging.WriteDebug(message);
            TypeHelper.Instance.ScanAssemblies(typeof(A_Initialization).Assembly);
            Bootstrap.Async().Wait();
            wan24.Crypto.Bootstrap.Boot();
            DisposableBase.CreateStackInfo = true;
            ErrorHandling.ErrorHandler = (info) =>
            {
                if(info.Exception is StackInfoException six) Logging.WriteError(six.StackInfo.Stack);
            };
            ValidateObject.Logger("wan24-Crypto Tests initialized");
        }
    }
}
