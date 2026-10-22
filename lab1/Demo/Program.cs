using Crypto.Bits;

Console.OutputEncoding = System.Text.Encoding.UTF8;

byte[] oneByte = { 0xB1 };                       // 1011 0001
int[] rotate = { 2, 3, 4, 5, 6, 7, 8, 1 };

Check("Сдвиг, MsbFirst с 1",
    BitPermutation.Permute(oneByte, rotate, BitOrder.MsbFirst, 1), "63");

Check("Сдвиг, LsbFirst с 1",
    BitPermutation.Permute(oneByte, rotate, BitOrder.LsbFirst, 1), "D8");

int[] rotateZero = { 1, 2, 3, 4, 5, 6, 7, 0 };
Check("Сдвиг, MsbFirst с 0",
    BitPermutation.Permute(oneByte, rotateZero, BitOrder.MsbFirst, 0), "63");

byte[] twoBytes = { 0xB1, 0x0F };
int[] swapBytes = { 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 };
Check("Обмен байтов, MsbFirst с 0",
    BitPermutation.Permute(twoBytes, swapBytes, BitOrder.MsbFirst, 0), "0FB1");

int[] duplicate = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
Check("Расширение 8 → 16 бит",
    BitPermutation.Permute(oneByte, duplicate, BitOrder.MsbFirst, 1), "B1B1");

static void Check(string name, byte[] actual, string expectedHex)
{
    string actualHex = Convert.ToHexString(actual);
    string status = actualHex == expectedHex ? "OK  " : "FAIL";
    Console.WriteLine($"[{status}] {name}: {actualHex} (ожидали {expectedHex})");
}