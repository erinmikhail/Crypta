namespace Crypto.Padding;


///<summary>add and remove набивки</summary>
public static class BlockPadding
{
    public static byte[] Apply(byte[] data, int blockSize, PaddingMode mode)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateBlockSize(blockSize);
        ValidateMode(mode);

        int remainder = data.Length % blockSize;

        if (mode == PaddingMode.Zeros && remainder == 0)
        {
            return (byte[])data.Clone();
        }

        int padLength = blockSize - remainder; // 1 до  blockSize
        byte[] result = new byte[data.Length + padLength];
        data.CopyTo(result, 0);

        int padStart = data.Length;
        int last = result.Length - 1;

        switch (mode)
        {
            case PaddingMode.Zeros:
                break;

            case PaddingMode.AnsiX923:
                result[last] = (byte)padLength;
                break;

            case PaddingMode.Pkcs7:
                Array.Fill(result, (byte)padLength, padStart, padLength);
                break;

            case PaddingMode.Iso10126:
                System.Security.Cryptography.RandomNumberGenerator.Fill(result.AsSpan(padStart, padLength - 1));
                result[last] = (byte)padLength;
                break;
        }

        return result;
    }

    ///<summary>убрать набивку при дешифр, длина data кратна blockSize</summary>
    public static byte[] Remove(byte[] data, int blockSize, PaddingMode mode)
    {
        ArgumentNullException.ThrowIfNull(data);
        ValidateBlockSize(blockSize);
        ValidateMode(mode);

        if (data.Length % blockSize != 0)
        {
            throw new ArgumentException("Длина данных не кратна размеру блока.", nameof(data));
        }

        if (mode == PaddingMode.Zeros)
        {
            return RemoveZeros(data, blockSize);
        }

        if (data.Length == 0)
        {
            throw new InvalidDataException("Нет данных: набивка должна занимать хотя бы один байт.");
        }

        int padLength = data[data.Length - 1];

        if (padLength < 1 || padLength > blockSize)
        {
            throw new InvalidDataException("Некорректная длина набивки");
        }

        int padStart = data.Length - padLength;

        switch (mode)
        {
            case PaddingMode.AnsiX923:
                for (int i = padStart; i < data.Length - 1; i++)
                {
                    if (data[i] != 0)
                    {
                        throw new InvalidDataException("Некорректная набивка ANSI X.923: не нулевой байт перед последним.");
                    }
                }
                break;

            case PaddingMode.Pkcs7:
                for (int i = padStart; i < data.Length; i++)
                {
                    if (data[i] != padLength)
                    {
                        throw new InvalidDataException("набивка Pkcs7 некорректна или повреждена.");
                    }
                }
                break;

            case PaddingMode.Iso10126:
                break;
        }

        return data[..padStart];
    }


    private static byte[] RemoveZeros(byte[] data, int blockSize)
    {
        int end = data.Length;
        int minEnd = Math.Max(0, data.Length - (blockSize - 1));

        while (end > minEnd && data[end - 1] == 0)
        {
            end--;
        }

        return data[..end];
    }

    private static void ValidateBlockSize(int blockSize)
    {
        if (blockSize < 1 || blockSize > 255)
        {
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Размер блока должен быть от 1 до 255 байт.");
        }
    }

    private static void ValidateMode(PaddingMode mode)
    {
        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode), "Недопустимый режим набивки.");
        }
    }
}
