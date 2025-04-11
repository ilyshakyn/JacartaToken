using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.CompilerServices;
using System.Runtime.Remoting;
using System.Security.AccessControl;


namespace ConsoleApp2
{
    class JaCartaCertificateManager
    {
        private IPkcs11Library _library;
        private ISlot _slot;

        public JaCartaCertificateManager(string libraryPath)
        {
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            _library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded);
            _slot = FindSlot(_library);
        }

        public void ImportCertificate(string certPath, string pin)
        {
            using (ISession session = _slot.OpenSession(SessionType.ReadWrite))
            {
                session.Login(CKU.CKU_USER, pin);
                var certData = ReadCertFromFile(certPath);
                var subject = GetX509Subject(certData);
                CreateCertFromBlob(session, certData, subject);
                session.Logout();
            }
        }

        private byte[] ReadCertFromFile(string certPath)
        {
            return File.ReadAllBytes(certPath);
        }

        private byte[] GetX509Subject(byte[] certData)
        {
            X509Certificate2 cert = new X509Certificate2(certData);
            return cert.SubjectName.RawData;
        }

        private void CreateCertFromBlob(ISession session, byte[] certData, byte[] subject)
        {
            var objectAttributes = new List<IObjectAttribute>()
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, subject),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, certData)
        };

            Net.Pkcs11Interop.HighLevelAPI.IObjectHandle certObject = session.CreateObject(objectAttributes);
            Console.WriteLine("сертефикат успешно импортирован на токен");
        }

        private ISlot FindSlot(IPkcs11Library library)
        {
            foreach (var slot in library.GetSlotList(SlotsType.WithTokenPresent))
            {
                if (slot.GetTokenInfo().TokenFlags.TokenInitialized)
                    return slot;
            }
            throw new Exception("токен не найден.");
        }
    }
    internal class Program
    {
        static void Main(string[] args)
        {
            // Путь к библиотеке PKCS#11
            string libraryPath = @"C:\Users\user\Desktop\Дипломка\JaCarta-2 GOST SDK 2.9.0.137\SDK\lib\Win32\jcPKCS11-2.dll";

            // Путь к сертификату
            string certPath = @"C:\Users\user\Desktop\Дипломка\certiki\dim_cert.cer";

            // ПИН-код для доступа к токену
            Console.WriteLine("12345");
            string pin = Console.ReadLine();
            //"123456"

            try
            {
                // Создание экземпляра менеджера сертификатов
                JaCartaCertificateManager manager = new JaCartaCertificateManager(libraryPath);

                // Импорт сертификата
                manager.ImportCertificate(certPath, pin);

                Console.WriteLine("импорт сетефиката успешно завершен");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"об ошибке: {ex.Message}");
            }

            // Задержка консоли
            Console.WriteLine("нажмите любую клавишу чтобы выйти");
            Console.ReadKey();
        }
    }
}

