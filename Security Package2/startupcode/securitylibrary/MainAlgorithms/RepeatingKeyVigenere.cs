using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int csize = cipherText.Length;
            string _englisghAlphabet = "abcdefghijklmnopqrstuvwxyz", _keyString = "", _tmp = "";
            int indx = 0;
            while (indx < csize) // pt = computer  ct = jsx...  key =  ct-pt    // get key
            {
                int x = (_englisghAlphabet.IndexOf(cipherText[indx]));
                int y = (_englisghAlphabet.IndexOf(plainText[indx]));
                int z = x - y;
                z = z + 26;
                z = z % 26;
                _keyString = _keyString + _englisghAlphabet[z];
                indx = indx + 1;
            }
            _tmp = _tmp + _keyString[0];
            int ksize = _keyString.Length;
            int indx2 = 1;
            do // check key valid
            {
                if (cipherText.Equals(Encrypt(plainText, _tmp)))
                {
                    return _tmp;
                }
                _tmp = _tmp + _keyString[indx2];
                indx2++;
            } while (indx2 < ksize);
            return _keyString;
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int _csize = cipherText.Length;
            string _plainTextString = "",
                   _englisghAlphabet = "abcdefghijklmnopqrstuvwxyz";
            int zero = 0;
            int _tmp = zero;
            while (key.Length != _csize)
            {
                key = key + key[_tmp];
                _tmp = _tmp + 1;
            }
            int indx = 0;
            do
            {
                int x = (_englisghAlphabet.IndexOf(cipherText[indx]));
                int y = (_englisghAlphabet.IndexOf(key[indx]));
                int z = x - y; // ct - keystream = pt
                z = z + 26;
                z = z % 26;
                _plainTextString = _plainTextString + _englisghAlphabet[z];
                indx = indx + 1;
            } while (indx < _csize);
            return _plainTextString;
        }
        public string Encrypt(string plainText, string key)
        {
            int x = 0 , psize = plainText.Length;
            string _CT = "",
                    _englishAlphabet = "abcdefghijklmnopqrstuvwxyz";
            while (key.Length != plainText.Length) // key = hello   p.t  = computer  == > keystream = hellohel
            {
                key = key + key[x];
                x = x + 1;
            }
            int indexatic = 0; // (c + h) = (j) "index"   (pt+keystream)%26 = ct
            do
            {
                int n1 = _englishAlphabet.IndexOf(plainText[indexatic]);
                int n2 = _englishAlphabet.IndexOf(key[indexatic]);
                n2 = n2 + n1;
                n2 = n2 % 26;
                _CT = _CT + _englishAlphabet[n2];
                indexatic = indexatic + 1;
            } while (indexatic < psize);
            return _CT;
        }
    }
}