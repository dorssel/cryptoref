using Dorssel.Security.Cryptography.Reference.SP_800_185.ExtensionMethods;
using System.Text;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("UnitTests")]

namespace Dorssel.Security.Cryptography.Reference.SP_800_185;

public class KMAC
{
    static string enc8(int i)
    {
        return Utilities.ToBitString(new[] { (byte)i }, 8);
    }

    static string right_encode(int x)
    {
        InputValidation.Assert(0 <= x);

        var n = 1;
        while (!((1 << (8 * n)) > x))
        {
            ++n;
        }
        var x_ = new int[n + 1];
        for (int i = 1; i <= n; ++i)
        {
            x_[i] = (x >> (8 * (n - i))) % 256;
        }
        var O_ = new string[n + 2];
        for (int i = 1; i <= n; ++i)
        {
            O_[i] = enc8(x_[i]);
        }
        O_[n + 1] = enc8(n);
        return string.Concat(Enumerable.Range(1, n + 1).Select(i => O_[i]));
    }

    static string left_encode(int x)
    {
        InputValidation.Assert(0 <= x);

        var n = 1;
        while (!((1 << (8 * n)) > x))
        {
            ++n;
        }
        var x_ = new int[n + 1];
        for (int i = 1; i <= n; ++i)
        {
            x_[i] = (x >> (8 * (n - i))) % 256;
        }
        var O_ = new string[n + 1];
        for (int i = 1; i <= n; ++i)
        {
            O_[i] = enc8(x_[i]);
        }
        O_[0] = enc8(n);
        return string.Concat(Enumerable.Range(0, n + 1).Select(i => O_[i]));
    }

    static string encode_string(string S)
    {
        InputValidation.BitString(S);

        return left_encode(S.Length) + S;
    }

    internal static string bytepad(string X, int w)
    {
        InputValidation.Assert(w > 0);

        var z = left_encode(w) + X;
        while (z.Length.Mod(8) != 0)
        {
            z = z + "0";
        }
        while ((z.Length / 8).Mod(w) != 0)
        {
            z = z + "00000000";
        }
        return z;
    }

    static readonly FIPS_202.KECCAK KECCAK = new();

    public static string cSHAKE128(string X, int L, string N, string S)
    {
        InputValidation.BitString(X);
        InputValidation.Assert(0 <= L);
        InputValidation.BitString(N);
        InputValidation.BitString(S);

        if (N == "" && S == "")
        {
            return FIPS_202.SHA3.SHAKE128(X, L);
        }
        else
        {
            return KECCAK[256](bytepad(encode_string(N) + encode_string(S), 168) + X + "00", L);
        }
    }

    public static string cSHAKE256(string X, int L, string N, string S)
    {
        InputValidation.BitString(X);
        InputValidation.Assert(0 <= L);
        InputValidation.BitString(N);
        InputValidation.BitString(S);

        if (N == "" && S == "")
        {
            return FIPS_202.SHA3.SHAKE256(X, L);
        }
        else
        {
            return KECCAK[512](bytepad(encode_string(N) + encode_string(S), 136) + X + "00", L);
        }
    }

    public static string KMAC128(string K, string X, int L, string S)
    {
        InputValidation.BitString(K);
        InputValidation.BitString(X);
        InputValidation.Assert(0 <= L);
        InputValidation.BitString(S);

        var newX = bytepad(encode_string(K), 168) + X + right_encode(L);
        var test = bytepad(encode_string(K), 168).ToBytes();
        return cSHAKE128(newX, L, Encoding.ASCII.GetBytes("KMAC").ToBitString(32), S);
    }

    public static string KMAC256(string K, string X, int L, string S)
    {
        InputValidation.BitString(K);
        InputValidation.BitString(X);
        InputValidation.Assert(0 <= L);
        InputValidation.BitString(S);

        var newX = bytepad(encode_string(K), 136) + X + right_encode(L);
        return cSHAKE256(newX, L, Encoding.ASCII.GetBytes("KMAC").ToBitString(32), S);
    }
}
