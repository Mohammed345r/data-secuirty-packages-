using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string _englishAlphabetic = "abcdefghijklmnopqrstuvwxyz", _keyString = "", _tString = "";
            int zero = 0;
            int s = zero, _resultVar = zero;
            int indx = 0;
            while (indx < cipherText.Length)
            {
                int x = _englishAlphabetic.IndexOf(cipherText[indx]), y = _englishAlphabetic.IndexOf(plainText[indx]);
                s = x - y + 26;
                _resultVar = s % 26;
                _keyString = _keyString + _englishAlphabetic[_resultVar];
                indx = indx + 1;
            }
            _tString = _tString + _keyString[0];
            int indx2 = 1;
            while (indx2 < _keyString.Length)
            {
                if (cipherText == Encrypt(plainText, _tString))
                {
                    return _tString;
                }
                _tString = _tString + _keyString[indx2];
                indx2 = indx2 + 1;
            }
            return _keyString;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string _englishAlphabetic = "abcdefghijklmnopqrstuvwxyz", _plainTextString = "";
            int zero = 0;
            int s = zero, _resultVar = zero;
            int indx = 0;
            while (indx < cipherText.Length)
            {
                int x = _englishAlphabetic.IndexOf(cipherText[indx]), y = _englishAlphabetic.IndexOf(key[indx]);
                s = x - y + 26; // to add 26 if s is negative
                _resultVar = s % 26;
                _plainTextString = _plainTextString + _englishAlphabetic[_resultVar];
                key = key + _plainTextString[indx];
                indx = indx + 1;
            }
            return _plainTextString;
        }

        public string Encrypt(string plainText, string key)
        {
            string _englishAlphabetic = "abcdefghijklmnopqrstuvwxyz", _CT = "";
            int  _cnt = 0, res = 0, s = 0;
            while (plainText.Length != key.Length)
            {
                key = key + plainText[_cnt];
                _cnt = _cnt + 1;
            }
            int indx = 0;
            while (indx < plainText.Length)
            {
                int x = _englishAlphabetic.IndexOf(plainText[indx]), y = _englishAlphabetic.IndexOf(key[indx]);
                s = x + y;
                res = s % 26;
                _CT = _CT + _englishAlphabetic[res];
                indx = indx + 1;

            }
            return _CT;
        }
    }
}
