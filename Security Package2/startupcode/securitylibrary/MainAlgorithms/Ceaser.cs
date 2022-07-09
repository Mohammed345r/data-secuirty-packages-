using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string _englishAlphabet = "abcdefghijklmnopqrstuvwxyz"; // english letters
        public int _numberOfLetters(char let) // mapping from letter to index number  a : 0  b : 1
        {
            int index = 0;
            do
            {
                int x = _englishAlphabet[index];
                if (let == x)
                {
                    return index;
                }
                index = index + 1;
            } while (index < 26);
            return -1;
        }
        public string Encrypt(string plainText, int key)
        {
            // get length of p.t
            int _lengthOfPlainText = plainText.Length;
            string _cipherText = "";
            int index = 0;
            do
            {
                if (char.IsLetter(plainText[index])) // a : 0  b : 1
                {
                    int _equationLetterIndex = ((key + _numberOfLetters(plainText[index])) % 26);
                    // c =(index[p] + key) % 26
                    _cipherText += char.ToUpper(_englishAlphabet[_equationLetterIndex]);
                    //update c.t
                }
                else // special character
                {
                    _cipherText = plainText[index] + _cipherText;
                }
                index = index + 1;
            } while (index < _lengthOfPlainText);

            return _cipherText; // get c.t

        }
        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int x = cipherText.Length;
            string _PlainText = "";
            int index = 0;
            do
            {
                if (char.IsLetter(cipherText[index]))
                {
                    int _equationLetterIndex = ((_numberOfLetters(cipherText[index]) - key) % 26);
                    // ct equation
                    if (_equationLetterIndex < 0) // if negative value
                    {
                        _equationLetterIndex = _equationLetterIndex + 26;
                    }
                    _PlainText += _englishAlphabet[_equationLetterIndex];
                }
                else //special
                {
                    _PlainText = _PlainText + cipherText[index];
                }
                index = index + 1;
            } while (index < x);
            return _PlainText;
        }
        public int Analyse(string plainText, string cipherText)
        {
            // plain[0] = 2 p.t
            // cipher[0] = 10 c.t
            // 8
            int
                 x = plainText.Length,
                 y = cipherText.Length,
                dif = _numberOfLetters(char.ToLower(cipherText[0])) - _numberOfLetters(plainText[0]);
            if (x != y)
            {
                return -1;
            }
            if (dif < 0)
            {
                return dif + 26;
            }
            else
            {
                return dif % 26;
            }
        }
    }
}