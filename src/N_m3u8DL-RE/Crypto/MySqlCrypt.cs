using N_m3u8DL_RE.Common.Util;

namespace N_m3u8DL_RE.Crypto;

public class MySqlCrypt
{
    public static byte[] DecodeCsv(string videoData)
    {
        var arr = videoData[30..].Split(["\r\n"], StringSplitOptions.None);
        var na = new List<string>();

        foreach (var a in arr)
        {
            na.AddRange(a.Split(','));
        }

        na.Reverse();
        return Convert.FromBase64String(string.Join("", na));
    }

    public static byte[] DecodeBmp(string videoData)
    {
        var hexSegment = videoData[54..];
        return HexUtil.HexToBytes(hexSegment);
    }
}