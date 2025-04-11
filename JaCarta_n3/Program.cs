using System;
using System.Collections.Generic;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Runtime.CompilerServices;
using System.Runtime.Remoting;
using System.Security.AccessControl;


namespace ConsoleApp3
{

    class TokenManager
    {
        private IPkcs11Library _library;
        private ISlot _slot;

        public TokenManager(string libraryPath)
        {
            var factories = new Pkcs11InteropFactories();
            _library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded);
            _slot = _library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault();
            if (_slot == null)
                throw new Exception("No slots with tokens found.");
        }

        private ISlot FindSlot(IPkcs11Library library)
        {
            foreach (var slot in library.GetSlotList(SlotsType.WithTokenPresent))
            {
                if (slot.GetTokenInfo().TokenFlags.TokenInitialized)
                    return slot;
            }
            throw new Exception("Token not found.");
        }





        public void ShowPrivateKey(string pemFilePath, string pin)
        {
            var privateKeyDer = ConvertPemToDer(File.ReadAllText(pemFilePath));

            using (var session = _slot.OpenSession(SessionType.ReadWrite))
            {
                session.Login(CKU.CKU_USER, pin);
                ShowPrivateKeyDirectly(session, privateKeyDer);
                session.Logout();
            }
        }

        private void ShowPrivateKeyDirectly(ISession session, byte[] privateKeyDer)
        {
            var rsaParams = ConvertDerToRsaParameters(privateKeyDer);



            var objectAttributes = new List<IObjectAttribute>
{
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, rsaParams.Modulus.ToByteArrayUnsigned()),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, rsaParams.PublicExponent.ToByteArrayUnsigned()),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE_EXPONENT, rsaParams.Exponent.ToByteArrayUnsigned()),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_1, rsaParams.P.ToByteArrayUnsigned()),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_2, rsaParams.Q.ToByteArrayUnsigned()),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_1, rsaParams.DP.ToByteArrayUnsigned()),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_2, rsaParams.DQ.ToByteArrayUnsigned()),
session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COEFFICIENT, rsaParams.QInv.ToByteArrayUnsigned())
};

            Console.WriteLine("Private Key Details:");
            Console.WriteLine($"Modulus (n): {rsaParams.Modulus.ToString()}");
            Console.WriteLine($"Public Exponent (e): {rsaParams.PublicExponent.ToString()}");
            Console.WriteLine($"Private Exponent (d): {rsaParams.Exponent.ToString()}");
            Console.WriteLine($"Prime 1 (p): {rsaParams.P.ToString()}");
            Console.WriteLine($"Prime 2 (q): {rsaParams.Q.ToString()}");
            Console.WriteLine($"Exponent 1 (d mod (p-1)): {rsaParams.DP.ToString()}");
            Console.WriteLine($"Exponent 2 (d mod (q-1)): {rsaParams.DQ.ToString()}");
            Console.WriteLine($"Coefficient (q^(-1) mod p): {rsaParams.QInv.ToString()}");
            try
            {
                Net.Pkcs11Interop.HighLevelAPI.IObjectHandle privateKeyHandle = session.CreateObject(objectAttributes);
                Console.WriteLine("Private key has been successfully imported directly in DER format.");
            }
            catch (Pkcs11Exception e)
            {
                Console.WriteLine($"Failed to import private key: {e.Message}");
            }
        }


        private byte[] ConvertPemToDer(string pem)
        {
            var header = "-----BEGIN PRIVATE KEY-----";
            var footer = "-----END PRIVATE KEY-----";
            var start = pem.IndexOf(header, StringComparison.Ordinal) + header.Length;
            var end = pem.IndexOf(footer, start, StringComparison.Ordinal);
            var base64 = pem.Substring(start, end - start);

            return Convert.FromBase64String(base64);
        }
        private RsaPrivateCrtKeyParameters ConvertDerToRsaParameters(byte[] privateKeyDer)
        {
            var privateKeyAsn1 = Asn1Object.FromByteArray(privateKeyDer);
            var privateKeyInfo = PrivateKeyInfo.GetInstance(privateKeyAsn1);
            var rsaParams = PrivateKeyFactory.CreateKey(privateKeyInfo) as RsaPrivateCrtKeyParameters;
            return rsaParams;
        }

        public void WriteFileToToken(string filePath, string tokenLabel, string pin)
        {
            byte[] fileContent = File.ReadAllBytes(filePath);
            using (var session = _slot.OpenSession(SessionType.ReadWrite))
            {
                session.Login(CKU.CKU_USER, pin);
                var objectAttributes = new List<IObjectAttribute>()
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_DATA),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, tokenLabel),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, fileContent)
        };

                var dataObjectHandle = session.CreateObject(objectAttributes);
                Console.WriteLine($"Файл '{filePath}'успешно записан на токен");

                session.Logout();
            }
        }

        public void FindAndSaveDataFromToken(string searchLabel, string savePath, string pin)
        {
            using (var session = _slot.OpenSession(SessionType.ReadOnly))
            {
                session.Login(CKU.CKU_USER, pin);
                var attributes = new List<IObjectAttribute>()
                 {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, searchLabel)
                 };
                session.FindObjectsInit(attributes);
                var foundObjects = session.FindObjects(1);
                session.FindObjectsFinal();

                if (foundObjects.Count > 0)
                {
                    var data = session.GetAttributeValue(foundObjects[0], new List<CKA>() { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                    File.WriteAllBytes(savePath, data);
                    Console.WriteLine($"информаия сохранена в  '{savePath}'.");
                }
                else
                {
                    Console.WriteLine("нет такого файла");
                }

                session.Logout();
            }
        }

        public void DeleteDataFromToken(string dataLabel, string pin)
        {
            using (var session = _slot.OpenSession(SessionType.ReadWrite))
            {
                session.Login(CKU.CKU_USER, pin);
                var attributes = new List<IObjectAttribute>()
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, dataLabel)
        };
                session.FindObjectsInit(attributes);
                var foundObjects = session.FindObjects(1);
                session.FindObjectsFinal();

                if (foundObjects.Count > 0)
                {
                    session.DestroyObject(foundObjects[0]);

                    Console.WriteLine("объекты удалены с токена.");
                }
                else
                {
                    Console.WriteLine("нет никакой информации на токене");
                }

                session.Logout();
            }
        }

    }
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Добро пожаловать в управление JaCarta токеном");
            Console.WriteLine("1: создание закрытого ключа");
            Console.WriteLine("2: Запись файла на токен");
            Console.WriteLine("3: Поиск и сохранение данных с токена");
            Console.WriteLine("4: Удаление данных с токена");
            Console.WriteLine("5: Выход");

            TokenManager manager = new TokenManager(@"C:\Users\user\Desktop\Дипломка\JaCarta-2 GOST SDK 2.9.0.137\SDK\lib\Win32\jcPKCS11-2.dll");
            string pin = "12345"; // Измените на ваш реальный PIN

            string option = Console.ReadLine();
            switch (option)
            {
                case "1":
                    Console.Write("Введите путь к PEM файлу: ");
                    string pemPath = Console.ReadLine();
                    manager.ShowPrivateKey(pemPath, pin);
                    break;
                case "2":
                    Console.Write("Введите путь к файлу для записи: ");
                    string filePath = Console.ReadLine();
                    Console.Write("Введите метку файла на токене: ");
                    string fileLabel = Console.ReadLine();
                    manager.WriteFileToToken(filePath, fileLabel, pin);
                    break;
                case "3":
                    Console.Write("Введите метку данных для поиска на токене: ");
                    string searchLabel = Console.ReadLine();
                    Console.Write("Введите путь для сохранения данных: ");
                    string savePath = Console.ReadLine();
                    manager.FindAndSaveDataFromToken(searchLabel, savePath, pin);
                    break;
                case "4":
                    Console.Write("Введите метку данных для удаления с токена: ");
                    string dataLabel = Console.ReadLine();
                    manager.DeleteDataFromToken(dataLabel, pin);
                    break;
                case "5":
                    return;
                default:
                    Console.WriteLine("Неверная опция, попробуйте снова.");
                    break;
            }
            Console.ReadLine();
        }
    }
}

