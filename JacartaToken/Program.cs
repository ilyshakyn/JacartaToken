using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using Net.Pkcs11Interop.Common;
using System.Threading;
using System.Security.AccessControl;


namespace ConsoleApp1
{


    internal class Program
    {

        static IPkcs11Library _pkcs11Library = null;
        static bool _wasInit = false;
        static void Init(string libraryPath)
        {
            try
            {

                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                _pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded);
                _wasInit = true;
                Console.WriteLine("Библиотека успешно инициализирована");
            }
            catch (Exception ex)
            {
                Leave($"Ошибка инициализации: {ex.Message}");
            }
        }
        static void Leave(string message)
        {
            Console.WriteLine(message);
            if (_wasInit && _pkcs11Library != null)
            {
                _pkcs11Library.Dispose();
                _pkcs11Library = null;
                _wasInit = false;
                Console.WriteLine("Ресурсы библиотеки успешно освобождены");
            }
        }

        static void DisplayTokenInfo(ulong slotId)
        {
            var slot = _pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault(s => s.SlotId == slotId);

            if (slot != null)
            {
                var tokenInfo = slot.GetTokenInfo();

                Console.WriteLine("Информация о токене:");
                Console.WriteLine($"Метка: {tokenInfo.Label}");
                Console.WriteLine($"Производитель: {tokenInfo.ManufacturerId}");
                Console.WriteLine($"Модель: {tokenInfo.Model}");
                Console.WriteLine($"Серийный номер: {tokenInfo.SerialNumber}");
                Console.WriteLine($"Максимальное количество сессий: {tokenInfo.MaxSessionCount}");
                Console.WriteLine($"Текущее количество сессий: {tokenInfo.SessionCount}");
                Console.WriteLine($"Максимальное количество сессий чтения/записи: {tokenInfo.MaxRwSessionCount}");
                Console.WriteLine($"Текущее количество сессий чтения/записи: {tokenInfo.RwSessionCount}");
                Console.WriteLine($"Максимальная длина PIN-кода: {tokenInfo.MaxPinLen}");
                Console.WriteLine($"Минимальная длина PIN-кода: {tokenInfo.MinPinLen}");
                Console.WriteLine($"Объем общедоступной памяти: {tokenInfo.TotalPublicMemory}");
                Console.WriteLine($"Свободно в общедоступной памяти: {tokenInfo.FreePublicMemory}");
                Console.WriteLine($"Объем приватной памяти: {tokenInfo.TotalPrivateMemory}");
                Console.WriteLine($"Свободно в приватной памяти: {tokenInfo.FreePrivateMemory}");
                Console.WriteLine($"Аппаратная версия: {tokenInfo.HardwareVersion}.{tokenInfo.HardwareVersion}");
                Console.WriteLine($"Версия прошивки: {tokenInfo.FirmwareVersion}.{tokenInfo.FirmwareVersion}");

                DisplayTokenFlags(slotId);

            }
            else
            {
                Console.WriteLine("Токен в указанном слоте не найден.");
            }
        }

        static void DisplayTokenFlags(ulong tokenID)
        {
            // Определение флагов
            const ulong CKF_WRITE_PROTECTED = 0x00000002;
            const ulong CKF_LOGIN_REQUIRED = 0x00000004;
            const ulong CKF_USER_PIN_INITIALIZED = 0x00000008;
            const ulong CKF_RESTORE_KEY_NOT_NEEDED = 0x00000020;
            const ulong CKF_CLOCK_ON_TOKEN = 0x00000040;
            const ulong CKF_PROTECTED_AUTHENTICATION_PATH = 0x00000100;
            const ulong CKF_DUAL_CRYPTO_OPERATIONS = 0x00000200;
            const ulong CKF_TOKEN_INITIALIZED = 0x00000400;
            const ulong CKF_SECONDARY_AUTHENTICATION = 0x00000800;
            const ulong CKF_USER_PIN_COUNT_LOW = 0x00010000;
            const ulong CKF_USER_PIN_FINAL_TRY = 0x00020000;
            const ulong CKF_USER_PIN_LOCKED = 0x00040000;
            const ulong CKF_USER_PIN_TO_BE_CHANGED = 0x00080000;
            const ulong CKF_SO_PIN_COUNT_LOW = 0x00100000;
            const ulong CKF_SO_PIN_FINAL_TRY = 0x00200000;
            const ulong CKF_SO_PIN_LOCKED = 0x00400000;
            const ulong CKF_SO_PIN_TO_BE_CHANGED = 0x00800000;

            Console.WriteLine("Флаги токена:");

            if ((tokenID & CKF_WRITE_PROTECTED) != 0) Console.WriteLine("Token защищен от записи.");
            if ((tokenID & CKF_LOGIN_REQUIRED) != 0) Console.WriteLine("Требуется вход пользователя для совершения операций.");
            if ((tokenID & CKF_USER_PIN_INITIALIZED) != 0) Console.WriteLine("Установлен пользовательский PIN.");
            if ((tokenID & CKF_RESTORE_KEY_NOT_NEEDED) != 0) Console.WriteLine("Не требуется ключ для восстановления криптографических операций.");
            if ((tokenID & CKF_CLOCK_ON_TOKEN) != 0) Console.WriteLine("На токене присутствуют внутренние часы.");
            if ((tokenID & CKF_PROTECTED_AUTHENTICATION_PATH) != 0) Console.WriteLine("Имеется возможность произвести аутентификацию без отправки PIN через библиотеку.");
            if ((tokenID & CKF_DUAL_CRYPTO_OPERATIONS) != 0) Console.WriteLine("Имеется возможность одновременного выполнения двух криптографических операций.");
            if ((tokenID & CKF_TOKEN_INITIALIZED) != 0) Console.WriteLine("Токен был инициализирован.");
            if ((tokenID & CKF_SECONDARY_AUTHENTICATION) != 0) Console.WriteLine("Токен поддерживает вторичную аутентификацию.");
            if ((tokenID & CKF_USER_PIN_COUNT_LOW) != 0) Console.WriteLine("Неправильный PIN был введен хотя бы раз с момента последней успешной аутентификации.");
            if ((tokenID & CKF_USER_PIN_FINAL_TRY) != 0) Console.WriteLine("При вводе некорректного PIN токен будет заблокирован.");
            if ((tokenID & CKF_USER_PIN_LOCKED) != 0) Console.WriteLine("Токен заблокирован для входа пользователя.");
            if ((tokenID & CKF_USER_PIN_TO_BE_CHANGED) != 0) Console.WriteLine("Установлен стандартный PIN или истек срок действия текущего PIN.");
            if ((tokenID & CKF_SO_PIN_COUNT_LOW) != 0) Console.WriteLine("Неправильный PIN администратора был введен хотя бы раз.");
            if ((tokenID & CKF_SO_PIN_FINAL_TRY) != 0) Console.WriteLine("При вводе некорректного PIN администратора токен будет заблокирован.");
            if ((tokenID & CKF_SO_PIN_LOCKED) != 0) Console.WriteLine("Вход администратора токена заблокирован.");
            if ((tokenID & CKF_SO_PIN_TO_BE_CHANGED) != 0) Console.WriteLine("Установлен стандартный PIN администратора или истек срок действия текущего PIN.");
        }



        static void DisplayLibraryInfo()
        {
            if (_pkcs11Library == null || !_wasInit)
            {
                Console.WriteLine("Библиотека не инициализирована.");
                return;
            }

            // Получение информации о библиотеке
            ILibraryInfo libraryInfo = _pkcs11Library.GetInfo();

            // Вывод информации о библиотеке
            Console.WriteLine($"Информация о библиотеке PKCS#11:");
            Console.WriteLine($"Производитель: {libraryInfo.ManufacturerId}");
            Console.WriteLine($"Описание библиотеки: {libraryInfo.LibraryDescription}");
            Console.WriteLine($"Версия интерфейса PKCS#11: {libraryInfo.CryptokiVersion}");
            Console.WriteLine($"Версия библиотеки: {libraryInfo.LibraryVersion}");
        }
        static void MonitorTokenEvents()
        {
            List<ulong> knownTokens = new List<ulong>();

            while (true)
            {
                var slots = _pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

                var currentTokens = new List<ulong>();

                foreach (var slot in slots)
                {
                    ulong slotId = slot.SlotId;
                    currentTokens.Add(slotId);

                    if (!knownTokens.Contains(slotId))
                    {
                        Console.WriteLine($"Обнаружен новый токен в слоте {slotId}.");
                        DisplayTokenInfo(slotId);
                    }
                }


                var removedTokens = knownTokens.Except(currentTokens).ToList();
                foreach (var removedToken in removedTokens)
                {
                    Console.WriteLine($"Токен был удален из слота {removedToken}.");
                }

                knownTokens = currentTokens;
                Thread.Sleep(1000);
            }
        }

        static void Main(string[] args)
        {
            string libraryPath = @"C:\Users\user\Desktop\Дипломка\JaCarta-2 GOST SDK 2.9.0.137\SDK\lib\Win32\jcPKCS11-2.dll";




            Init(libraryPath);
            DisplayLibraryInfo();




            MonitorTokenEvents();




            Console.ReadLine();


        }
    }
}

