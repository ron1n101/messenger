#include "base64.h"
#include "crypto_exception.h"
#include <openssl/evp.h>
#include <climits>

namespace {
    bool isBase64Char (char c)
    {
        return (c >= 'A' && c <= 'Z')
            || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9')
            || c == '+'
            || c == '/';
    }
}

std::string CryptoUtils::base64Encode(const Bytes &data)
{
        // ---- Шаг 1. Пустые данные -> пустая строка.
    if (data.empty())
    {
        return std::string();
    }
    

    // ---- Шаг 2. EVP_EncodeBlock принимает длину как int (знакомая проверка из AES-CBC).
    // Берём INT_MAX / 2 с запасом: результат длиннее входа на треть.
    // ВПИШИ: если data.size() > INT_MAX / 2 — CryptoException("base64Encode: input too large");
    if (data.size() > INT_MAX / 2)
    {
        throw CryptoException ("Base64Encode: Input too large");
    }

    // ---- Шаг 3. Буфер под результат: 4 * ((n + 2) / 3) символов + 1 под '\0' (теория 1.4).
    // (n + 2) / 3 — это деление с округлением ВВЕРХ.
    // ВПИШИ: std::string out(<размер>, '\0');
    std::string out (4 * (data.size() + 2) / 3 + 1, '\0');


    // ---- Шаг 4. Кодирование.
    // EVP_EncodeBlock(куда, откуда, длина) работает с unsigned char*.
    // Указатель на символы строки: &out[0]; превратить в unsigned char*: reinterpret_cast<unsigned char *>(&out[0]).
    // ВПИШИ: const int written = EVP_EncodeBlock(...);
    const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&out [0]), data.data(), static_cast<int>(data.size()));

    // ---- Шаг 5. written < 0 -> исключение; иначе обрезать out до written и вернуть.
    // ВПИШИ.
    if (written < 0)
    {
        throw CryptoException ("Base64Encode: EVP_EncodeBlock");
    }
    else{
        out.resize(written);
        return out;
    }
}

void CryptoUtils::base64Decode(const std::string &text, Bytes &output)
{
    // ---- Шаг 1. Пустая строка -> пустые байты.
    // ВПИШИ.
    if (text.empty())
    {
        output.clear();
        return;
    }

    // ---- Шаг 2. Длина должна быть кратна 4.
    // ВПИШИ: CryptoException("base64Decode: length is not a multiple of 4");

    if (text.size() % 4 != 0)
    {
        throw CryptoException ("base64Decode: length is not a multiple pf 4");
    }

    // ---- Шаг 3. Проверка на INT_MAX (как в шаге 2 кодирования, только без / 2).
    // ВПИШИ.
    if (text.size () > INT_MAX)
    {
        throw CryptoException ("base64Decode: input too large");
    }

    // ---- Шаг 4. Считаем '=' в конце: смотрим на последний и предпоследний символ.
    size_t padding = 0;
    // ВПИШИ: если последний символ '=' — padding++;
    // ВПИШИ: если предпоследний символ '=' — padding++;
    if (text[text.size() - 1] == '=')
    {
        padding++;
    }
    if (text[text.size() - 2] == '=')
    {
        padding ++;
    }

    // ---- Шаг 5. Всё, кроме этих '=' в конце, должно быть из алфавита (теория 1.4, пункт 3).
    // Так отсекаются пробелы, переносы строк и '=' в середине.
    // ВПИШИ: цикл по i от 0 до text.size() - padding; если !isBase64Char(text[i]) —
    //        CryptoException("base64Decode: invalid character");
    for (size_t i = 0; i < text.size() - padding; i++)
    {
        if(!isBase64Char(text[i]))
        {
            throw CryptoException ("base64Decode: invalid character");
        }

    }

    // ---- Шаг 6. Буфер: каждые 4 символа дают максимум 3 байта.
    // ВПИШИ: Bytes out(text.size() / 4 * 3);
    Bytes out (text.size() / 4 * 3);

    // ---- Шаг 7. Декодирование.
    // EVP_DecodeBlock(куда, откуда, длина): «откуда» — reinterpret_cast<const unsigned char *>(text.data()).
    // ВПИШИ: const int written = EVP_DecodeBlock(...);
    // ВПИШИ: written < 0 -> CryptoException("base64Decode: EVP_DecodeBlock failed");
    const int written = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(text.data()), static_cast<int>(text.size()));
    if (written < 0 )
    {
        throw (CryptoException ("base64Decode: EVP_DecodeBlock failed"));
    }
    else{
        out.resize(static_cast<size_t>(written) - padding);
        output.swap(out);
        return;
    }


    // ---- Шаг 8. DecodeBlock посчитала '=' нулевыми байтами — вычитаем их (теория 1.4, пункт 2).
    // ВПИШИ: out.resize(static_cast<size_t>(written) - padding);
    // ВПИШИ: return out;
    
}