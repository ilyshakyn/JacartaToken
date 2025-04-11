using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI41;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Remoting;
using System.Security.AccessControl;
using System.Text;

namespace ConsoleApp4
{
    internal class Program
    {
        private static string libraryPath = @"C:\Users\user\Desktop\Дипломка\JaCarta-2 GOST SDK 2.9.0.137\SDK\lib\Win32\jcPKCS11-2.dll";
        private static string pin = "12345"; // Ваш PIN
        private static string filePath = @"C:\Users\user\source\repos\ConsoleApp1\ConsoleApp4\bin\Debug\1.txt";



        public static void Main(string[] args)
        {
            string text = File.ReadAllText(filePath);

            // Вывод текста на консоль
            Console.WriteLine(text);
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (var pkcs11 = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded))
            {
                var slots = pkcs11.GetSlotList(SlotsType.WithTokenPresent);
                using (var session = slots[0].OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, pin);

                    // Поиск или создание ключа DES3
                    IObjectHandle des3Key = CreateSessionKey(session, factories);


                    Console.WriteLine("Введите 1 для шифрования файла, 2 для расшифрования:");
                    while (1 == 1)
                    {
                        var choice = Console.ReadLine();

                        if (choice == "1")
                        {


                            byte[] data = File.ReadAllBytes(filePath);

                            if (data.Length < 128)
                            {
                                Array.Resize(ref data, 128);
                            }
                            Array.Resize(ref data, 128);

                            byte[] encryptedData = EncryptData(session, des3Key, data, factories);
                            File.WriteAllBytes(filePath, encryptedData);
                            string text1 = File.ReadAllText(filePath);

                            // Вывод текста на консоль
                            Console.WriteLine(text1);
                            Console.WriteLine("Данные зашифрованы и сохранены.");
                        }
                        else if (choice == "2")
                        {
                            byte[] encryptedData = File.ReadAllBytes(filePath);
                            byte[] decryptedData = DecryptData(session, des3Key, encryptedData, factories);
                            File.WriteAllBytes(filePath, decryptedData);
                            string text2 = File.ReadAllText(filePath);

                            // Вывод текста на консоль
                            Console.WriteLine(text2);
                            Console.WriteLine("Данные расшифрованы и сохранены.");
                        }
                        else
                        {
                            Console.WriteLine("Неверный ввод. Пожалуйста, введите 1 или 2.");
                        }
                    }



                    session.Logout();
                    Console.ReadLine();
                }
            }
        }

        private static IObjectHandle CreateSessionKey(ISession session, Pkcs11InteropFactories factories)
        {
            // Устанавливаем критерии поиска для нахождения DES3 ключа
            List<IObjectAttribute> searchAttributes = new List<IObjectAttribute>()
    {
        factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
        factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3),
        factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "MyDES3Key")
    };

            // Начинаем поиск объектов по заданным атрибутам
            session.FindObjectsInit(searchAttributes);
            List<IObjectHandle> foundKeys = session.FindObjects(1); // Попытка найти хотя бы один ключ
            session.FindObjectsFinal(); // Завершаем операцию поиска

            if (foundKeys.Count > 0)
            {
                // Если ключ найден, возвращаем его
                return foundKeys[0];
            }
            else
            {
                // Если ключ не найден, создаем новый ключ DES3
                List<IObjectAttribute> keyAttributes = new List<IObjectAttribute>()
        {
            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
