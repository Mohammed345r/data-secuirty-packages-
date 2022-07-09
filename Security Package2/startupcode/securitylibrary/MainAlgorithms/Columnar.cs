using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            {
                cipherText = cipherText.ToLower();
                plainText = plainText.ToLower();
                List<int> key = new List<int>();
                int _R1 = 0, _C1 = 0, _OutI = 0;
                do
                {
                    if (cipherText[0] == plainText[_OutI])
                    {
                        int _In2 = _OutI + 1;
                        while (_In2 < cipherText.Length)
                        {
                            if (cipherText[1] == plainText[_In2])
                            {
                                int _In3 = _OutI + 2;
                                while (_In3 < cipherText.Length)
                                {
                                    if (cipherText[2] == plainText[_In3])
                                    {
                                        int _In4 = _OutI + 3;
                                        int CipTLn = cipherText.Length;
                                        while (_In4 < CipTLn)
                                        {
                                            if (cipherText[3] == plainText[_In4])
                                            {
                                                if (_In2 - _OutI != _In3 - _In2)
                                                {
                                                    break;
                                                }
                                                else
                                                {
                                                    _C1 = _In3 - _In2;
                                                    bool _cond1 = CipTLn % _C1 > 0, _cond2 = CipTLn % _C1 < 0;
                                                    if (_cond1 || _cond2)
                                                    {
                                                        _R1 = CipTLn / _C1;
                                                        _R1 += 1;
                                                    }
                                                    else
                                                    {
                                                        _R1 = CipTLn / _C1;
                                                        break;
                                                    }
                                                }
                                            }
                                            _In4 += 1;
                                        }
                                    }
                                    _In3 += 1;
                                }
                            }
                            _In2 += 1;
                        }
                    }
                    _OutI += 1;
                } while (_OutI < cipherText.Length);
                char[,] arrayplaintext = new char[_R1, _C1];
                int _LnCon = 0, _theFIn = 0, _LnConI = 0;
                do
                { for (int j = 0; j < _C1; j++) if (_LnCon < plainText.Length) arrayplaintext[_theFIn, j] = plainText[_LnCon++]; _theFIn++; }
                while (_theFIn < _R1);

                int _theFIIn = 0;
                while (_theFIIn < _C1)
                {
                    for (int k = 0; k < cipherText.Length; k++)
                    {
                        if (arrayplaintext[0, _theFIIn] == cipherText[k])
                        {
                            if (arrayplaintext[1, _theFIIn] == cipherText[k + 1])
                            {
                                if (arrayplaintext[2, _theFIIn] == cipherText[k + 2])
                                {
                                    _LnConI = k / _R1;
                                    bool InCond1 = k % _R1 > 0, InCond2 = k % _R1 < 0;
                                    if (InCond1 || InCond2)
                                    {
                                        _LnConI += 1;
                                    }
                                    key.Add(_LnConI + 1);
                                    break;
                                }
                            }
                        }
                    }
                    _theFIIn += 1;
                }
                List<int> FinalLK = key;
                return FinalLK;
            }
        }
        public string Decrypt(string cipherText, List<int> key)
        {
            // ct/key = number of row
            // max number in key ==> number of char in one row
            int _col = key.Count, zerovar = 0, carctr = zerovar, _numOfRow = (int)Math.Ceiling(cipherText.Length / (float)_col), multi = _numOfRow * _col;
            string s = "";
            char[,] array = new char[_col, _numOfRow];
            if (multi != cipherText.Length)
            {
                zerovar++;
            }
            else
            {

                int indx = 0;
                do // assign 2d 
                {
                    for (int indx2 = 0; indx2 < _numOfRow; indx2++) array[indx, indx2] = cipherText[carctr++];
                    indx = indx + 1;
                } while (indx != _col);
                int indx3 = 0;
                do // write
                {
                    for (int indx4 = 0; indx4 < _col; indx4++) s += array[key[indx4] - 1, indx3]; indx3++;
                } while (indx3 != _numOfRow);
            }
            return s;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int _cols = key.Count;
            string _ET = "";
            string[] arr = new string[50];
            int v1 = 0, v2 = 0, v3 = 0;
            while (v3 < _cols) // to breakdown
            {
                // v3    col
                // v1    row
                v1 = v3; // 0 0
                int indx3 = v1;
                do
                {
                    if (v1 < plainText.Length)
                    {
                        arr[key[v2] - 1] = arr[key[v2] - 1] + plainText[v1]; // c o m p u 
                        v1 = v1 + _cols;
                    }
                    indx3 = indx3 + 1;
                } while (indx3 < plainText.Length); 
                v2 = v2 + 1;
                v3 = v3 + 1;
            }
            int indx2 = 0; // to write ct by column
            do
            {
                _ET = _ET + arr[indx2];
                indx2 = indx2 + 1;
            } while (indx2 < _cols);
            return _ET;
        }
    }
}