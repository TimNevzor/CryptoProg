#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iomanip>

std::string sha256(const std::string& str) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(str, 	//читает строку str
    true, 							//автоматически обрабатывает данные
    new CryptoPP::HashFilter(hash, 	//фильтр, применяющий хэш-функцию к данным. hash - ф-ция для вычисления хэша
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));//преобразует байты хэша в 16-ый формат и записывает в digest

    return digest;
}

std::string readfile(const std::string& filename) {
    std::ifstream file(filename);
    std::ostringstream stroka;

    if (file) { //если файл открылся - записывает в строку всё его содержимое
        stroka << file.rdbuf();
    } else {
        std::cerr << "Ошибка открытия файла" << std::endl;
    }
	file.close();
    return stroka.str();
}

int main() {
    const std::string filename = "text.txt";
    std::string strfile = readfile(filename);
    std::string hash = sha256(strfile);
    std::cout << "SHA256 : " << hash << std::endl;
    return 0;
}
