#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;
using namespace std;

// Генерация ключа из пароля
SecByteBlock generateKey(const string& password)
{
    SecByteBlock key(AES::MAX_KEYLENGTH); //key с максимальной длиной ключа для AES 256 бит
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2; //для использования алгоритма PBKDF2 с SHA256
    pbkdf2.DeriveKey(
        key, key.size(), 0,
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(), //указатели на данные и длину пароля 
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
        16384 // количество итераций для усложнения взлома
    );
    return key;
}

// Шифрование
void encryptFile(const string& infile, const string& outfile, const string& password)
{
    SecByteBlock key = generateKey(password);
    SecByteBlock iv(AES::BLOCKSIZE); //объект iv для хранения инициализационного вектора IV размером блока AES 16 байт

    AutoSeededRandomPool prng; //генератор случайных чисел для генерации IV
    prng.GenerateBlock(iv, iv.size()); //генерирует случайный IV и записывается в iv

    ofstream encryptedFile(outfile, ios::binary);

    // Записываем IV в начало файла
    encryptedFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());

    CBC_Mode<AES>::Encryption encryptor; //объект encryptor для шифрования с использованием режима CBC и алгоритма AES
    encryptor.SetKeyWithIV(key, key.size(), iv); //устанавливает ключ и IV для шифрования


    FileSource(infile.c_str(), true,
               new StreamTransformationFilter(encryptor, //данные шифруются с использованием encryptor и записываются в encryptedFile
                       new FileSink(encryptedFile))); //StreamTransformationFilter применет шифрование к каждому блоку
}

// Расшифрование
void decryptFile(const string& inputFile, const string& outputFile, const string& password)
{
    SecByteBlock key = generateKey(password);
    SecByteBlock iv(AES::BLOCKSIZE);

    ifstream encryptedFile(inputFile, ios::binary);

    // Считываем IV из начала файла
    encryptedFile.read(reinterpret_cast<char*>(iv.data()), iv.size());

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);

    FileSource(encryptedFile, true,
               new StreamTransformationFilter(decryptor,
                       new FileSink(outputFile.c_str())));
}

int main()
{
    while(true) {
        std::string infile;
        std::string outfile;
        std::string password;
        std::cout << "Введите 1 для зашифрования, 2 для расшифрования, 0 для выхода: " << std::endl;
        std::string op;
        std::cin >> op;

        if(op == "0") {
            std::cout << "До свидания" << std::endl;
            break;
        }

        if(op == "1") {

            while(true) {
                std::cout << "Введите файл с исходным текстом: " << std::endl;
                std::cin >> infile;

                std::ifstream file(infile);
                if (!file) {
                    std::cerr << "Файл не существует" << std::endl;
                } else {
                    break;
                }
            }

            while(true) {
                std::cout << "Введите файл, в который нужно сохранить зашифрованный текст: " << std::endl;
                std::cin >> outfile;

                std::ifstream file(outfile);
                if (!file) {
                    std::cerr << "Файл не существует" << std::endl;
                } else {
                    break;
                }
            }

            std::cout << "Введите пароль: " << std::endl;
            std::cin >> password;
            encryptFile(infile, outfile, password);
            std::cout << "Файл успешно зашифрован" << std::endl;
        }

        if(op == "2") {

            while(true) {
                std::cout << "Введите файл с исходным текстом: "<<std::endl;
                std::cin >> infile;

                std::ifstream file(infile);
                if (!file) {
                    std::cerr << "Файл не существует" << std::endl;
                } else {
                    break;
                }
            }

            while(true) {
                std::cout << "Введите файл, в который нужно сохранить рашифрованный текст: " << std::endl;
                std::cin >> outfile;

                std::ifstream file(outfile);
                if (!file) {
                    std::cerr << "Файл не существует" << std::endl;
                } else {
                    break;
                }
            }

            std::cout << "Введите пароль: " << std::endl;
            std::cin >> password;
            decryptFile(infile, outfile, password);
            std::cout << "Файл успешно расшифрован" << std::endl;
        }

        if((op != "0") && (op != "1") && (op != "2")) {
            std::cout << "Некорректная операция" << std::endl;
        }

    }

    return 0;
}
