using System.Text;
using N_m3u8DL_RE.Common.Log;
using NiL.JS.BaseLibrary;
using NiL.JS.Core;
using NiL.JS.Extensions;
using Array = System.Array;

namespace N_m3u8DL_RE.Crypto;

public class AkamaiPlayerIn
{
    public static string DecodeTsa(string encodedText)
    {
        var result = new StringBuilder(encodedText.Length);
        foreach (var t in encodedText)
        {
            result.Append((char)(t - 20));
        }

        return result.ToString();
    }

    public static string DecodeTsb(string encodedText)
    {
        var result = new StringBuilder(encodedText.Length);
        foreach (var t in encodedText)
        {
            result.Append((char)((t >> 3) ^ 0x2a));
        }

        return result.ToString();
    }

    public static string DecodeTsc(string encodedText)
    {
        var result = new StringBuilder(encodedText.Length);
        foreach (var t in encodedText)
        {
            result.Append((char)(t - 10));
        }

        return result.ToString();
    }

    public static string DecodeTsd(string encodedText)
    {
        var result = new StringBuilder(encodedText.Length);
        foreach (var t in encodedText)
        {
            result.Append((char)(t >> 2));
        }

        return result.ToString();
    }

    public static string DecodeTse(string encodedText)
    {
        var result = new StringBuilder(encodedText.Length);
        foreach (var t in encodedText)
        {
            result.Append((char)((t ^ 0x2a) >> 3));
        }

        return result.ToString();
    }

    private static SortedDictionary<int, bool> TIMEOUTS_ACTIVE = new SortedDictionary<int, bool>();
    
    private static uint GetUInt32BigEndian(byte[] data, int offset)
    {
        var temp = data[offset..(offset + 4)];
        Array.Reverse(temp);
        return BitConverter.ToUInt32(temp, 0);
    }

    private static byte[] ConvertKey(byte[] key)
    {
        uint[] uint32Array = [
            GetUInt32BigEndian(key, 0), 
            GetUInt32BigEndian(key, 4), 
            GetUInt32BigEndian(key, 8), 
            GetUInt32BigEndian(key, 12)
        ];

        var result = new byte[16];
        for (var i = 0; i < 4; i++)
        {
            Array.Copy(BitConverter.GetBytes(uint32Array[i]), 0, result, i * 4, 4);
        }
        return result;
    }
    
    public static void DecryptSegment(byte[] bytes, byte[] key, byte[] iv, string fileName, int threadCount)
    {
        if (threadCount != 1)
        {
            Logger.Error("Only single thread operations are supported. Use --thread-count 1");
            Environment.Exit(1);
        }
        var eventClass = new EventClass();
        var context = new Context();
        
        context.DefineVariable("setTimeout").Assign(Context.CurrentGlobalContext.ProxyValue(
            (ICallable callback, int delay) =>
            {
                lock (TIMEOUTS_ACTIVE)
                {
                    var id = Random.Shared.Next();
                    while (TIMEOUTS_ACTIVE.ContainsKey(id))
                    {
                        id++;
                    }
                    TIMEOUTS_ACTIVE[id] = true;

                    Task.Delay(delay).ContinueWith(_ =>
                    {
                        lock (TIMEOUTS_ACTIVE)
                        {
                            TIMEOUTS_ACTIVE.Remove(id);
                            callback.Call(null, null);
                        }
                    });

                    return id;
                }
            }
        ));
        context.DefineVariable("objectWithEvent").Assign(context.GlobalContext.ProxyValue(eventClass));
        context.Eval(JS);
        
        var decrypt = context.GetVariable("startProcess").As<Function>();
        decrypt.Call(new Arguments { bytes, ConvertKey(key), ConvertKey(iv), fileName });
    }

    private class EventClass
    {
        public void FireEvent(byte[] data, string fileName)
        {
            File.WriteAllBytes(fileName[..^4], data);
        }
    }
    
    private static string JS =
        """
        var CONSTANTS = null;
        
        function generateConstants() {
          var _0x16df3f = [
            [[], [], [], [], []], 
            [[], [], [], [], []]
          ];
        
          var _0x120614 = _0x16df3f[0x0];
          var _0x375658 = _0x16df3f[0x1];
          var _0x184814 = _0x120614[0x4];
          var _0x39dbd7 = _0x375658[0x4];
        
          var _0x4ba018 = [];
          var _0xa51a5a = [];
        
          var _0x24bd61;
          var _0x2b6016;
          var _0x4cc6ef;
        
          for (var i = 0x0; i < 0x100; i++) {
            _0xa51a5a[(_0x4ba018[i] = i << 0x1 ^ (i >> 0x7) * 0x11b) ^ i] = i;
          }
        
          var a;
          var b;
          for (a = b = 0x0; !_0x184814[a]; a ^= _0x24bd61 || 0x1, b = _0xa51a5a[b] || 0x1) {
            var _0x32741b = b ^ b << 0x1 ^ b << 0x2 ^ b << 0x3 ^ b << 0x4;
            var _0x32741b = _0x32741b >> 0x8 ^ _0x32741b & 0xff ^ 0x63;
        
            _0x184814[a] = _0x32741b;
            _0x39dbd7[_0x32741b] = a;
            _0x4cc6ef = _0x4ba018[_0x2b6016 = _0x4ba018[_0x24bd61 = _0x4ba018[a]]];
        
            var _0x3290f1 = _0x4cc6ef * 0x1010101 ^ _0x2b6016 * 0x10001 ^ _0x24bd61 * 0x101 ^ a * 0x1010100;
            var _0x480d54 = _0x4ba018[_0x32741b] * 0x101 ^ _0x32741b * 0x1010100;
        
            for (var i = 0x0; i < 0x4; i++) {
              _0x120614[i][a] = _0x480d54 = _0x480d54 << 0x18 ^ _0x480d54 >>> 0x8;
              _0x375658[i][_0x32741b] = _0x3290f1 = _0x3290f1 << 0x18 ^ _0x3290f1 >>> 0x8;
            }
          }
        
          for (var i = 0x0; i < 0x5; i++) {
            _0x120614[i] = _0x120614[i].slice(0x0);
            _0x375658[i] = _0x375658[i].slice(0x0);
          }
        
          return _0x16df3f;
        };

        class Decryptor {
          constructor(key) {
            if (!CONSTANTS) {
              CONSTANTS = generateConstants();
            }
        
            this._tables = [
              [CONSTANTS[0x0][0x0].slice(), CONSTANTS[0x0][0x1].slice(), CONSTANTS[0x0][0x2].slice(), CONSTANTS[0x0][0x3].slice(), CONSTANTS[0x0][0x4].slice()], 
              [CONSTANTS[0x1][0x0].slice(), CONSTANTS[0x1][0x1].slice(), CONSTANTS[0x1][0x2].slice(), CONSTANTS[0x1][0x3].slice(), CONSTANTS[0x1][0x4].slice()]
            ];
        
            var _0x234690;
            var _0x220a21 = this._tables[0x0][0x4];
            var _0x121987 = this._tables[0x1];
            
            var aesKeySize = key.length;
            var _0x390570 = 0x1;
        
            if (aesKeySize !== 0x4 && aesKeySize !== 0x6 && aesKeySize !== 0x8) {
              throw new Error("Invalid aes key size");
            }
        
            var _0x3c8236 = key.slice(0x0);
            var _0x964d78 = [];
        
            this._key = [_0x3c8236, _0x964d78];
        
            for (var i = aesKeySize; i < 0x4 * aesKeySize + 0x1c; i++) {
              _0x234690 = _0x3c8236[i - 0x1];
              if (i % aesKeySize === 0x0 || aesKeySize === 0x8 && i % aesKeySize === 0x4) {
                _0x234690 = _0x220a21[_0x234690 >>> 0x18] << 0x18 ^ _0x220a21[_0x234690 >> 0x10 & 0xff] << 0x10 ^ _0x220a21[_0x234690 >> 0x8 & 0xff] << 0x8 ^ _0x220a21[_0x234690 & 0xff];
                if (i % aesKeySize === 0x0) {
                  _0x234690 = _0x234690 << 0x8 ^ _0x234690 >>> 0x18 ^ _0x390570 << 0x18;
                  _0x390570 = _0x390570 << 0x1 ^ (_0x390570 >> 0x7) * 0x11b;
                }
              }
              _0x3c8236[i] = _0x3c8236[i - aesKeySize] ^ _0x234690;
            }
            for (var a = 0x0; i; a++, i--) {
              _0x234690 = _0x3c8236[a & 0x3 ? i : i - 0x4];
              if (i <= 0x4 || a < 0x4) {
                _0x964d78[a] = _0x234690;
              } else {
                _0x964d78[a] = _0x121987[0x0][_0x220a21[_0x234690 >>> 0x18]] ^ _0x121987[0x1][_0x220a21[_0x234690 >> 0x10 & 0xff]] ^ _0x121987[0x2][_0x220a21[_0x234690 >> 0x8 & 0xff]] ^ _0x121987[0x3][_0x220a21[_0x234690 & 0xff]];
              }
            }
          }
        
          decrypt(_0x3e9fd5, _0xb0e3c1, _0x5eb1e9, _0x4ea233, _0x83def8, _0x256f00) {
            var _0x491237 = this._key[0x1];
        
            var _0x299fe2 = _0x3e9fd5 ^ _0x491237[0x0];
            var _0x58213a = _0x4ea233 ^ _0x491237[0x1];
            var _0x125c05 = _0x5eb1e9 ^ _0x491237[0x2];
            var _0x2c1c2c = _0xb0e3c1 ^ _0x491237[0x3];
        
            var _0x3b9018 = 0x4;
            var _0x534cd9 = this._tables[0x1];
        
            var _0xed214f = _0x534cd9[0x0];
            var _0x4817f5 = _0x534cd9[0x1];
            var _0x469e18 = _0x534cd9[0x2];
            var _0x4ab84e = _0x534cd9[0x3];
            var _0x14dd19 = _0x534cd9[0x4];
        
            for (var i = 0x0; i < _0x491237.length / 0x4 - 0x2; i++) {
              var _0x2e9ec9 = _0xed214f[_0x299fe2 >>> 0x18] ^ _0x4817f5[_0x58213a >> 0x10 & 0xff] ^ _0x469e18[_0x125c05 >> 0x8 & 0xff] ^ _0x4ab84e[_0x2c1c2c & 0xff] ^ _0x491237[_0x3b9018];
              var _0x3a863d = _0xed214f[_0x58213a >>> 0x18] ^ _0x4817f5[_0x125c05 >> 0x10 & 0xff] ^ _0x469e18[_0x2c1c2c >> 0x8 & 0xff] ^ _0x4ab84e[_0x299fe2 & 0xff] ^ _0x491237[_0x3b9018 + 0x1];
              var _0x3173a2 = _0xed214f[_0x125c05 >>> 0x18] ^ _0x4817f5[_0x2c1c2c >> 0x10 & 0xff] ^ _0x469e18[_0x299fe2 >> 0x8 & 0xff] ^ _0x4ab84e[_0x58213a & 0xff] ^ _0x491237[_0x3b9018 + 0x2];
              _0x2c1c2c = _0xed214f[_0x2c1c2c >>> 0x18] ^ _0x4817f5[_0x299fe2 >> 0x10 & 0xff] ^ _0x469e18[_0x58213a >> 0x8 & 0xff] ^ _0x4ab84e[_0x125c05 & 0xff] ^ _0x491237[_0x3b9018 + 0x3];
        
              _0x3b9018 += 0x4;
              _0x299fe2 = _0x2e9ec9;
              _0x58213a = _0x3a863d;
              _0x125c05 = _0x3173a2;
            }
        
            for (var i = 0x0; i < 0x4; i++) {
              _0x83def8[(0x3 & -i) + _0x256f00] = _0x14dd19[_0x299fe2 >>> 0x18] << 0x18 ^ _0x14dd19[_0x58213a >> 0x10 & 0xff] << 0x10 ^ _0x14dd19[_0x125c05 >> 0x8 & 0xff] << 0x8 ^ _0x14dd19[_0x2c1c2c & 0xff] ^ _0x491237[_0x3b9018++];
              _0x2e9ec9 = _0x299fe2;
              _0x299fe2 = _0x58213a;
              _0x58213a = _0x125c05;
              _0x125c05 = _0x2c1c2c;
              _0x2c1c2c = _0x2e9ec9;
            }
          };
        };

        class DecryptManager {
          constructor() {
            this.jobs = [];
            this.delay = 1;
            this.timeout_ = null;
          }
        
          processJob_() {
            this.jobs.shift()();
            if (this.jobs.length) {
              this.timeout_ = setTimeout(this.processJob_.bind(this), this.delay);
            } else {
              this.timeout_ = null;
            }
          };
        
          push(data) {
            this.jobs.push(data);
            if (!this.timeout_) {
              this.timeout_ = setTimeout(this.processJob_.bind(this), this.delay);
            }
          };
        }
        
        function decryptChunk(_0x31b398, _0x375a2a, _0x26cd64) {
          var _0xec4572 = new Decryptor(Array.prototype.slice.call(_0x375a2a));
        
          var _0x341309 = new Int32Array(_0x31b398.buffer, _0x31b398.byteOffset, _0x31b398.byteLength >> 0x2);
          var _0xece511 = new Uint8Array(_0x31b398.byteLength);
          var _0x5acb81 = new Int32Array(_0xece511.buffer);
        
          var _0x4846f2 = _0x26cd64[0x0];
          var _0x24b0fe = _0x26cd64[0x1];
          var _0x20f9ef = _0x26cd64[0x2];
          var _0x26208c = _0x26cd64[0x3];
        
          for (var i = 0x0; i < _0x341309.length; i += 0x4) {
            var _0x4a6cfc = _0x341309[i] << 0x18 | (_0x341309[i] & 0xff00) << 0x8 | (_0x341309[i] & 0xff0000) >> 0x8 | _0x341309[i] >>> 0x18;
            var _0x38194e = _0x341309[i + 0x1] << 0x18 | (_0x341309[i + 0x1] & 0xff00) << 0x8 | (_0x341309[i + 0x1] & 0xff0000) >> 0x8 | _0x341309[i + 0x1] >>> 0x18;
            var _0x449b06 = _0x341309[i + 0x2] << 0x18 | (_0x341309[i + 0x2] & 0xff00) << 0x8 | (_0x341309[i + 0x2] & 0xff0000) >> 0x8 | _0x341309[i + 0x2] >>> 0x18;
            var _0x3e49e6 = _0x341309[i + 0x3] << 0x18 | (_0x341309[i + 0x3] & 0xff00) << 0x8 | (_0x341309[i + 0x3] & 0xff0000) >> 0x8 | _0x341309[i + 0x3] >>> 0x18;
        
            _0xec4572.decrypt(_0x4a6cfc, _0x38194e, _0x449b06, _0x3e49e6, _0x5acb81, i);
        
            _0x5acb81[i] = (_0x5acb81[i] ^ _0x4846f2) << 0x18 | ((_0x5acb81[i] ^ _0x4846f2) & 0xff00) << 0x8 | ((_0x5acb81[i] ^ _0x4846f2) & 0xff0000) >> 0x8 | (_0x5acb81[i] ^ _0x4846f2) >>> 0x18;
            _0x5acb81[i + 0x1] = (_0x5acb81[i + 0x1] ^ _0x24b0fe) << 0x18 | ((_0x5acb81[i + 0x1] ^ _0x24b0fe) & 0xff00) << 0x8 | ((_0x5acb81[i + 0x1] ^ _0x24b0fe) & 0xff0000) >> 0x8 | (_0x5acb81[i + 0x1] ^ _0x24b0fe) >>> 0x18;
            _0x5acb81[i + 0x2] = (_0x5acb81[i + 0x2] ^ _0x20f9ef) << 0x18 | ((_0x5acb81[i + 0x2] ^ _0x20f9ef) & 0xff00) << 0x8 | ((_0x5acb81[i + 0x2] ^ _0x20f9ef) & 0xff0000) >> 0x8 | (_0x5acb81[i + 0x2] ^ _0x20f9ef) >>> 0x18;
            _0x5acb81[i + 0x3] = (_0x5acb81[i + 0x3] ^ _0x26208c) << 0x18 | ((_0x5acb81[i + 0x3] ^ _0x26208c) & 0xff00) << 0x8 | ((_0x5acb81[i + 0x3] ^ _0x26208c) & 0xff0000) >> 0x8 | (_0x5acb81[i + 0x3] ^ _0x26208c) >>> 0x18;
        
            _0x4846f2 = _0x4a6cfc;
            _0x24b0fe = _0x38194e;
            _0x20f9ef = _0x449b06;
            _0x26208c = _0x3e49e6;
          }
        
          return _0xece511;
        };
        
        class Main {
          constructor(data, key, iv, callBackFunction) {
            var stepSize = 32000;
        
            var encryptedData = new Int32Array(data.buffer);
            var dataLength = new Uint8Array(data.byteLength);
        
            this.asyncStream_ = new DecryptManager();
        
            this.asyncStream_.push(
              this.decryptChunk_(encryptedData.subarray(0, stepSize), key, iv, dataLength)
            );
        
            for (var i = stepSize; i < encryptedData.length; i += stepSize) {
              iv = new Uint32Array(
                [
                  encryptedData[i - 0x4] << 0x18 | (encryptedData[i - 0x4] & 0xff00) << 0x8 | (encryptedData[i - 0x4] & 0xff0000) >> 0x8 | encryptedData[i - 0x4] >>> 0x18, 
                  encryptedData[i - 0x3] << 0x18 | (encryptedData[i - 0x3] & 0xff00) << 0x8 | (encryptedData[i - 0x3] & 0xff0000) >> 0x8 | encryptedData[i - 0x3] >>> 0x18, 
                  encryptedData[i - 0x2] << 0x18 | (encryptedData[i - 0x2] & 0xff00) << 0x8 | (encryptedData[i - 0x2] & 0xff0000) >> 0x8 | encryptedData[i - 0x2] >>> 0x18, 
                  encryptedData[i - 0x1] << 0x18 | (encryptedData[i - 0x1] & 0xff00) << 0x8 | (encryptedData[i - 0x1] & 0xff0000) >> 0x8 | encryptedData[i - 0x1] >>> 0x18
                ]
              );
              this.asyncStream_.push(
                this.decryptChunk_(encryptedData.subarray(i, i + stepSize), key, iv, dataLength)
              );
            }
        
            this.asyncStream_.push(function () {
              callBackFunction(
                null, 
                dataLength.subarray(
                  0, 
                  dataLength.byteLength - dataLength[dataLength.byteLength - 0x1]
                )
              );
            });
          }
        
          decryptChunk_(data, key, iv, dataLength) {
            return function () {
              var _0x4a1e3f = decryptChunk(data, key, iv);
              dataLength.set(_0x4a1e3f, data.byteOffset);
            };
          };
        
        };

        function startProcess(encrypted, key, iv, fileName){
          new Main(
            new Uint8Array(encrypted), 
            new Uint32Array(new Uint8Array(key).buffer),
            new Uint32Array(new Uint8Array(iv).buffer),
            function (_0x117711, decrypted) {
              objectWithEvent.FireEvent(decrypted, fileName);
            }
          );
        }
        """;
}
