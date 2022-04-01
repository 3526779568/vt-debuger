#ifndef MYFX_CBigInt_H__89650B57_0325_45C6_BFC5_AA1BDBF03FC0__INCLUDED_
#define MYFX_CBigInt_H__89650B57_0325_45C6_BFC5_AA1BDBF03FC0__INCLUDED_
#include <string>
using namespace std;

#define SL_BI_MAXLEN 38
#define SL_DEC 10
#define SL_HEX 16
class CBigInt
{
public:
	CBigInt();
	~CBigInt();
	unsigned m_nLength;
	unsigned long m_ulValue[SL_BI_MAXLEN];
	void Mov(unsigned __int64 A);
	void Mov(CBigInt& A);
	CBigInt Add(CBigInt& A);
	CBigInt Sub(CBigInt& A);
	CBigInt Mul(CBigInt& A);
	CBigInt Div(CBigInt& A);
	CBigInt Mod(CBigInt& A);
	CBigInt Add(unsigned long A);
	CBigInt Sub(unsigned long A);
	CBigInt Mul(unsigned long A);
	CBigInt Div(unsigned long A);
	unsigned long Mod(unsigned long A);
	int Cmp(CBigInt& A);
	void Get(string& str, unsigned int system = SL_HEX);
	void Put(string& str, unsigned int system = SL_HEX);
	CBigInt ExpMod(CBigInt& A, CBigInt& B);

};

//最高支持1024位
string CBigIntRSA(string v_data_16, string v_key16, string v_Mod16);



#endif
