namespace Crypto.Padding;

/// <summary>набивки посл блока.</summary>
public enum PaddingMode
{
    /// <summary>Добивание нулями. Набивка не добавляется, если данные кратны блоку. Неоднозначна, если данные сами заканчиваются нулями.</summary>
    Zeros,
    /// <summary>ANSI X.923: нули, последний байт — длина набивки.</summary>
    AnsiX923,
    /// <summary>PKCS#7: все байты набивки равны её длине.</summary>
    Pkcs7,
    /// <summary>ISO 10126: случайные байты, последний байт — длина набивки.</summary>
    Iso10126
}