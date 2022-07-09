using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
//using MathNet.Numerics.LinearAlgebra;
//using MathNet.Numerics.LinearAlgebra.Double;
//using MathNet.Numerics.LinearAlgebra.Factorization;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int Nl = 2, _Count = 0;
            int[,] _thePainT = new int[Nl, (plainText.Count / Nl)];
            int[,] _theCipherT = new int[Nl, (cipherText.Count / Nl)];
            int[,] key = new int[Nl, Nl];
            int i = 0, cond1 = (plainText.Count / Nl);
            while (i < cond1)
            {
                int j = 0;
                while (j < Nl)
                {
                    _thePainT[j, i] = plainText[_Count];
                    _theCipherT[j, i] = cipherText[_Count++];
                    j++;
                }
                i++;
            }
            int[,] plainTempT1 = new int[Nl, Nl];
            float[,] plainTempT2 = new float[Nl, Nl];
            int[,] cipherT1 = new int[Nl, Nl];
            i = 0;
            int cond2 = cond1 - 1;
            while (i < cond2)
            {
                plainTempT1[0, 0] = _thePainT[0, i];
                plainTempT1[1, 0] = _thePainT[1, i];
                cipherT1[0, 0] = _theCipherT[0, i];
                cipherT1[1, 0] = _theCipherT[1, i];
                int j = i + 1;
                for (; j < cond1; j++)
                {
                    plainTempT1[0, 1] = _thePainT[0, j];
                    plainTempT1[1, 1] = _thePainT[1, j];
                    cipherT1[0, 1] = _theCipherT[0, j];
                    cipherT1[1, 1] = _theCipherT[1, j];
                    double _detMat = Determinant_matrix(Nl, plainTempT1);
                    _detMat = _detMat % 26;
                    if (_detMat < 0)
                        _detMat += 26;
                    int _InvD = 0;
                    _InvD = Inverse_mat((int)_detMat);
                    bool con = (_InvD == -101);
                    if (con)
                        continue;
                    if (_InvD < 0)
                        _InvD += 26;
                    float A, B, C, D;
                    A = (plainTempT1[0, 0]);
                    B = (plainTempT1[0, 1]);
                    C = (plainTempT1[1, 0]);
                    D = (plainTempT1[1, 1]);
                    int _MatrixInv = 0;
                    _MatrixInv = (int)_InvD;
                    A = A * _MatrixInv;
                    D = D * _MatrixInv;
                    B = _MatrixInv * -1 * B;
                    C = _MatrixInv * -1 * C;
                    A %= 26; B %= 26; C %= 26; D %= 26;
                    if (A < 0 || B < 0 || C < 0 || D < 0)
                        A += 26;
                    plainTempT2[1, 1] = A;
                    plainTempT2[0, 1] = B;
                    plainTempT2[1, 0] = C;
                    plainTempT2[0, 0] = D;
                    List<int> _keyOfList = new List<int>();
                    List<int> _theCipherCond = new List<int>();
                    _keyOfList = Muti_matrix(2, plainTempT2, cipherT1);
                    _theCipherCond = Encrypt(plainText, _keyOfList);
                    int count = 0, k = 0;
                    while (k < plainText.Count)
                    {
                        if (_theCipherCond[k] == cipherText[k])
                            count++;
                        k += 1;
                    }
                    if (count == plainText.Count)
                        return _keyOfList;

                }
                i += 1;
            }
            

            throw new InvalidAnlysisException();
        }
        int Inverse_mat(int b)
        {
            int A1 = 1, A2 = 0, A3 = 26, B1 = 0, B2 = 1, B3 = b;
            double T1, T2, T3, Q;
            while (true)
            {
                switch (B3)
                {
                    case 0:
                        return -101;
                        break;
                    case 1:
                        return B2;
                        break;
                }
                Q = A3 / B3;
                T1 = A1 - Q * B1;
                T2 = A2 - Q * B2;
                T3 = A3 - Q * B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = (int)T1;
                B2 = (int)T2;
                B3 = (int)T3;
            }

        }
        List<int> Muti_matrix(int n, float[,] PlainText, int[,] CipherText)
        {

            double[,] key = new double[n, n];
            int i = 0;
            while (i < n)
            {
                int j = 0;
                while (j < n)
                {
                    key[i, j] = 0;
                    int k = 0;
                    while (k < n)
                    {

                        key[i, j] = key[i, j] + CipherText[i, k] * PlainText[k, j];
                        k++;
                    }
                    key[i, j] %= 26;
                    j++;
                }
                i++;
            }

            List<int> _NewKey = new List<int>();
            i = 0;
            while (i < n)
            {
                int j = 0;
                while (j < n)
                {
                    _NewKey.Add((int)key[i, j]);
                    j += 1;
                }
                i += 1;
            }
            return _NewKey;
        }
        //------------------
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            // List<int> key1 = new List<int>(key.Count);
            int _CSQ = Convert.ToInt32(Math.Sqrt(key.Count));
            int[,] _keyOfMat = new int[_CSQ, _CSQ];
            int _Count = 0;
            for (int i = 0; i < _CSQ;)
            {
                int j = 0;
                for (; j < _CSQ;)
                {
                    bool _con1 = (key[_Count] >= 0), _con2 = (key[_Count] <= 26);
                    if (_con1 && _con2)
                        _keyOfMat[i, j] = key[_Count++];
                    else if (key[_Count] > 26)
                    {
                        int x = key[_Count];
                        x = x % 26;
                        _keyOfMat[i, j] = x;
                        _Count++;
                    }
                    else
                    {
                        break;
                    }
                    j += 1;
                }
                i += 1;
            }
            double _OutRes = Determinant_matrix(_CSQ, _keyOfMat);
            _OutRes = _OutRes % 26;
            if (_OutRes < 0)
                _OutRes = _OutRes + 26;

            int _GcdRes = Greatest_common_divisor((int)_OutRes);
            //TESTCASE : HillCipherError3
            // No common factors between det(k) and 26(GCD(26, det(k)) = 1)

            if (_GcdRes != 1)
                throw new Exception();

            if (_CSQ == 2)
            {
                float _theInv = 0;
                float A, B, C, D;
                A = (_keyOfMat[0, 0]);
                B = (_keyOfMat[0, 1]);
                C = (_keyOfMat[1, 0]);
                D = (_keyOfMat[1, 1]);
                _theInv = 1 / ((A * D) - (B * C));
                A = A * _theInv; D = D * _theInv;
                B = B * _theInv * -1; C = C * _theInv * -1;
                key[0] = (int)D;
                key[1] = (int)B;
                key[2] = (int)C;
                key[3] = (int)A;
                return Encrypt(cipherText, key);
            }
            double c = 0, b = 0, d = 26 - _OutRes; _Count = 1;
            for (int i = 0; i < cipherText.Count; i++)
            {
                int _InnerOp = (26 * _Count + 1);
                double _theInncon = _InnerOp % d;
                if (_theInncon != 0)
                    _Count += 1;
                else
                    break;
            }
            c = (26 * _Count + 1) / d;
            b = 26 - c;
            int[,] _theInnerMat = new int[_CSQ - 1, _CSQ - 1];
            double[,] keyMatrixOutput = new double[_CSQ, _CSQ];
            int Lenj = 0, Leni = 0;

            // loop el k de btlef 3l el row

            for (int i = 0; i < 3;)
            {
                int j = 0;
                while (j < 3)
                {
                    int II = 0, III = 0, x = 0;
                    for (; x < 3; x++)
                        for (int y = 0; y < 3;)
                        {
                            bool InCon3 = (x == i || y == j);
                            if (!InCon3)
                            {
                                _theInnerMat[II, III] = _keyOfMat[x, y];
                                III++;
                                II = II + (III / 2);
                                III %= 2;
                            }
                            y += 1;
                        }
                    double _theAnsPowD = (b * (Math.Pow(-1, (i + j)) * (Determinant_matrix(_CSQ - 1, _theInnerMat))) % 26);
                    if (_theAnsPowD < 0)
                        _theAnsPowD += 26;
                    keyMatrixOutput[Leni, Lenj] = _theAnsPowD;
                    Lenj += 1;
                    if (Lenj > 2)
                    {
                        Lenj = 0; Leni += 1;
                    }
                    j += 1;
                }
                i += 1;
            }
            int _R2 = keyMatrixOutput.GetLength(0), _C2 = keyMatrixOutput.GetLength(1);
            double[,] _FiRes = new double[_C2, _R2];
            for (int i = 0; i < _R2;)
            {
                int j = 0;
                while (j < _C2)
                {
                    _FiRes[j, i] = keyMatrixOutput[i, j];
                    j += 1;
                }
                i += 1;
            }
            keyMatrixOutput = _FiRes;
            _Count = 0;
            for (int i = 0; i < _CSQ;)
            {
                for (int j = 0; j < _CSQ;)
                {
                    key[_Count] = (int)keyMatrixOutput[i, j];
                    _Count++; j++;
                }
                i += 1;
            }
            List<int> _theFinalResult = Encrypt(cipherText, key);
            return _theFinalResult;
        }

        public double Determinant_matrix(int m, int[,] keyMatrix)
        {

            int[,] _InnerMat = new int[m - 1, m - 1];
            double det = 0;
            switch (m)
            {
                case 2:
                    return ((keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[1, 0] * keyMatrix[0, 1]));
                    break;
                case 3:
                    int k = 0;
                    while (k < m)
                    {
                        int InnerI = 0, i = 1;
                        for (; i < m;)
                        {
                            int InnerJ = 0, j = 0;
                            for (; j < m; j++)
                            {
                                if (j == k)
                                {
                                    continue;
                                }
                                _InnerMat[InnerI, InnerJ] = keyMatrix[i, j];
                                InnerJ++;
                            }
                            InnerI += 1;
                            i += 1;
                        }
                        double res = Determinant_matrix(m - 1, _InnerMat);
                        double _powOp = (Math.Pow(-1, k) * keyMatrix[0, k] * res);
                        det = det + _powOp;
                        k++;
                    }
                    break;
            }
            return det;
        }
        public double[,] Transpose(double[,] matrix)
        {
            int _R1 = matrix.GetLength(0);
            int _C1 = matrix.GetLength(1);

            double[,] result = new double[_C1, _R1];
            int i = 0;
            while (i < _R1)
            {
                int j = 0;
                while (j < _C1)
                {
                    result[i, j] = matrix[i, j];
                    j += 1;
                }
                i += 1;
            }

            return result;
        }

        private static int Greatest_common_divisor(int x)
        {
            int y = 26;
            while (x != 0 && y != 0)
            {
                if (x > y)
                    x = x % y;
                else
                    y = y % x;
            }
            int _desc = (x == 0 ? y : x);
            return _desc;

        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> _CipherT = new List<int>(plainText.Count);
            int i = 0;
            while (i < plainText.Count)
            {
                _CipherT.Add(0);
                i += 1;
            }
            int n = (int)Math.Sqrt(key.Count), _length = 0;
            i = 0;
            while (i < plainText.Count)
            {
                int count = 0, value = 0, j = 0;
                for (; j <= key.Count;)
                {
                    bool _condOut = (count == n);
                    if (_condOut)
                    {
                        value = value % 26;
                        if (value < 0)
                            value += 26;
                        _CipherT[_length] = value;
                        count = 0; value = 0; _length += 1;
                        bool _condIn = (j == key.Count);
                        if (_condIn)
                            break;
                    }
                    value = value + (plainText[i + count] * key[j]);
                    count += 1; j += 1;
                }
                i += n;
            }
            return _CipherT;
        }
        //----------------
        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int _PltSq = (int)Math.Sqrt(plainText.Count);
            double[,] _theCipherTMat = new double[_PltSq, _PltSq];
            int _Ln = 0;
            for (int i = 0; i < _PltSq;)
            {
                int j = 0;
                while (j < _PltSq)
                {
                    bool _cond1 = (cipherText[_Ln] >= 0) && (cipherText[_Ln] <= 26), _cond2 = cipherText[_Ln] > 26;
                    if (_cond1)
                        _theCipherTMat[j, i] = cipherText[_Ln++];
                    else if (_cond2)
                    {
                        int x = cipherText[_Ln];
                        x = x % 26;
                        _theCipherTMat[j, i] = x;
                        _Ln += 1;
                    }
                    else
                    {
                        break;
                    }
                    j += 1;
                }
                i += 1;
            }

            int[,] _thePlainTMat = new int[_PltSq, _PltSq];
            _Ln = 0;
            for (int i = 0; i < _PltSq; i++)
            {
                int j = 0;
                while (j < _PltSq)
                {
                    bool _condi1 = (plainText[_Ln] >= 0) && (plainText[_Ln] <= 26), _condi2 = plainText[_Ln] > 26;
                    if (_condi1)
                        _thePlainTMat[i, j] = plainText[_Ln++];
                    else if (_condi2)
                    {
                        int x = plainText[_Ln];
                        x %= 26;
                        _thePlainTMat[i, j] = x;
                        _Ln++;
                    }
                    else
                    {
                        break;
                    }
                    j += 1;
                }
            }
            double _detMPl = Determinant_matrix(_PltSq, _thePlainTMat);
            _detMPl = _detMPl % 26;
            if (_detMPl < 0)
                _detMPl = _detMPl + 26;
            int _theGcdPl = Greatest_common_divisor((int)_detMPl);
            if (_theGcdPl != 1)
                throw new Exception();
            double c = 0, b = 0, d = 26 - _detMPl;
            _Ln = 1;
            for (int i = 0; i < plainText.Count; i++)
            {
                int ConRes1 = (26 * _Ln + 1);
                double ConR = ConRes1 % d;
                if (ConR != 0)
                    _Ln++;
                else
                    break;
            }
            c = (26 * _Ln + 1) / d; b = 26 - c;
            int[,] _MatOfSub = new int[_PltSq - 1, _PltSq - 1];
            double[,] _OuterMatPlainT = new double[_PltSq, _PltSq];
            int theOutJ = 0, theOutI = 0;

            for (int i = 0; i < 3;)
            {
                int j = 0;
                while (j < 3)
                {
                    int II = 0, III = 0, x = 0;
                    for (; x < 3; x++)
                        for (int y = 0; y < 3;)
                        {
                            if (!(x == i || y == j))
                            {
                                _MatOfSub[II, III] = _thePlainTMat[x, y];
                                III++; II = II + (III / 2); III = III % 2;
                            }
                            y += 1;
                        }
                    double _FiRes = (b * (Math.Pow(-1, (i + j)) * Determinant_matrix(_PltSq - 1, _MatOfSub)) % 26);
                    if (_FiRes < 0)
                        _FiRes += 26;
                    _OuterMatPlainT[theOutI, theOutJ] = _FiRes;
                    theOutJ++;
                    if (theOutJ > 2)
                    {
                        theOutJ = 0;
                        theOutI += 1;
                    }
                    j += 1;
                }
                i += 1;
            }
            _OuterMatPlainT = Transpose(_OuterMatPlainT);
            int _Cln = (int)Math.Sqrt(cipherText.Count);
            double[,] key = new double[_PltSq, _Cln];
            for (int i = 0; i < 3; i++)
            {
                int j = 0;
                for (; j < _PltSq;)
                {
                    key[i, j] = 0; int k = 0;
                    while (k < _PltSq)
                    {
                        key[i, j] = key[i, j] + (_theCipherTMat[j, k] * _OuterMatPlainT[k, i]);
                        key[i, j] = key[i, j] % 26;
                        k += 1;
                    }
                    j += 1;
                }
            }
            List<int> _KeyValues = new List<int>(9);
            int z = 0;
            while (z < 3)
            {
                int j = 0;
                while (j < 3)
                {
                    _KeyValues.Add((int)key[j, z]);
                    j -= -1;
                }
                z -= -1;
            }
            return _KeyValues;
        }
    }
}
