using System.Diagnostics;
using System.Numerics;

namespace Crypto2.NumberTheory;

public sealed class NumberTheoryService
{
    public BigInteger Gcd(BigInteger a, BigInteger b)
    {
        a = Abs(a);
        b = Abs(b);

        while (!b.IsZero)
        {
            BigInteger r = a % b;
            a = b;
            b = r;
        }

        return a;
    }

    private static BigInteger Abs(BigInteger x) => x.Sign < 0 ? -x : x;

    public (BigInteger Gcd, BigInteger X, BigInteger Y) ExtendedGcd(BigInteger a, BigIntegerInteger b)
    {
        BigInteger oldR = Abs(a), r = Abs(b);
        BigInteger oldX = 1, x = 0;
        BigInteger oldY = 0, y = 1;

        while (!r.IsZero)
        {
            BigInteger quotient = oldR / r;

            (oldR, r) = (r, oldR - quotient * r);
            (oldX, x) = (x, oldX - quotient * x);
            (oldY, y) = (y, oldY - quotient * y);
        }

        if (a.Sign < 0) oldX = -oldX;
        if (b.Sign < 0) oldY = -oldY;

        return (oldR, oldX, oldY);
    }

    public BigInteger Mod(BigInteger value, BigInteger modules)
    {
        if (modules.Sign <= 0)
        {
            throw new ArgumentException("Modules must be positive.", nameof(modules));
        }

        BigInteger result = value % modules;
        return result.Sign < 0 ? result + modules : result;
    }

    public BigInteger ModInverse(BigInteger a, BigInteger modules)
    {
        if (modules.Sign <= 0)
        { 
            throw new ArgumentException("Modules must be positive.", nameof(modules));
        }
        var (gcd, x, _) = ExtendedGcd(a, modules);

        if (gcd != 1)
        {
            throw new ArgumentException("Inverse does not exist.", nameof(a));
        }

        return Mod(x, modules);
    }
}