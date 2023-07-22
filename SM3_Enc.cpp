#include <iostream>
#include <cstring>
#include "SM3_class"
#include <fstream>

#include <vector>
#include <iomanip>
#include <memory>
#include <stdint.h>
#include <ctime>
#include <ratio>

#include <chrono>
#include <stdlib.h>
using namespace std;


#define MAX_NUM 1024*1024
#define MAXSIZE 1024*MAX_NUM

//设定加密文件的最大字节数为4KB
//超过该字节数，该程序会自动进行分块
//分为若干文本片段进行分别加密


unsigned int hash_result = 0;
//总的消息块
unsigned int Rate_of_hash = 0;
//当前已经计算完成hash的文本数据比例



static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)
//首先程序需要判断运行环境是否为小端
#define LeftRotate(word, bits) ( (word) << (bits) | (word) >> (32 - (bits)) )
//遵循sm3的标准加密方案，向左循环移位，同时反转四字节整型字节序

unsigned int* Reverse_word(unsigned int* word)
{
	unsigned char* byte, temp;

	byte = (unsigned char*)word;
	temp = byte[0];
	byte[0] = byte[3];
	byte[3] = temp;

	temp = byte[1];
	byte[1] = byte[2];
	byte[2] = temp;
	return word;

}
//接下来分别实现sm3的各个部件
//T
unsigned int T(int i)
{
	if (i >= 0 && i <= 15)
		return 0x79CC4519;
	else if (i >= 16 && i <= 63)
		return 0x7A879D8A;
	else
		return 0;
}

//FF
unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (X & Z) | (Y & Z);
	else
		return 0;
}

//GG
unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
	if (i >= 0 && i <= 15)
		return X ^ Y ^ Z;
	else if (i >= 16 && i <= 63)
		return (X & Y) | (~X & Z);
	else
		return 0;
}

//P0
unsigned int P0(unsigned int X)
{
	return X ^ LeftRotate(X, 9) ^ LeftRotate(X, 17);
}

//P1
unsigned int P1(unsigned int X)
{
	return X ^ LeftRotate(X, 15) ^ LeftRotate(X, 23);
}

//对sm3进行初始化函数
void SM3_Init(SM3::SM3Context* context) {
	context->intermediateHash[0] = 0x7380166F;
	context->intermediateHash[1] = 0x4914B2B9;
	context->intermediateHash[2] = 0x172442D7;
	context->intermediateHash[3] = 0xDA8A0600;
	context->intermediateHash[4] = 0xA96F30BC;
	context->intermediateHash[5] = 0x163138AA;
	context->intermediateHash[6] = 0xE38DEE4D;
	context->intermediateHash[7] = 0xB0FB0E4E;
}

// 对input的文本进行分块处理
void SM3_dealwith_MessageBlock(SM3::SM3Context* context)
{
	int i;
	unsigned int W[68];
	unsigned int W_[64];
	unsigned int A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;

	//message extence 
	for (i = 0; i < 16; i++)
	{
		W[i] = *(unsigned int*)(context->messageBlock + i * 4);
		if (IsLittleEndian())
			ReverseWord(W + i);
	}
	for (i = 16; i < 68; i++)
	{
		//P1
		W[i] = (W[i - 16] ^ W[i - 9] ^ LeftRotate(W[i - 3], 15)) ^ LeftRotate((W[i - 16] ^ W[i - 9] ^ LeftRotate(W[i - 3], 15)), 15) ^ LeftRotate((W[i - 16] ^ W[i - 9] ^ LeftRotate(W[i - 3], 15)), 23)
			^ LeftRotate(W[i - 13], 7)
			^ W[i - 6];
	}
	for (i = 0; i < 64; i++)
	{
		W_[i] = W[i] ^ W[i + 4];
	}
	if (i < 12) {
		W[i + 4] = *(unsigned int*)(context->messageBlock + (i + 4) * 4);
		if (IsLittleEndian())	ReverseWord(W + i + 4);
	}
	else {
		W[i + 4] = ((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)) ^ LeftRotate((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)), 15) ^ LeftRotate((W[i - 12] ^ W[i - 5] ^ LeftRotate(W[i + 1], 15)), 23)) ^ LeftRotate(W[i - 9], 7) ^ W[i - 2];
	}

	//message compression
	A = context->intermediateHash[0];
	B = context->intermediateHash[1];
	C = context->intermediateHash[2];
	D = context->intermediateHash[3];
	E = context->intermediateHash[4];
	F = context->intermediateHash[5];
	G = context->intermediateHash[6];
	H = context->intermediateHash[7];

	for (i = 0; i < 64; i++)
	{
		unsigned int SS3;

		SS1 = LeftRotate((LeftRotate(A, 12) + E + LeftRotate(T(i), i)), 7);
		SS2 = SS1 ^ LeftRotate(A, 12);
		TT1 = FF(A, B, C, i) + D + SS2 + W_[i];
		TT2 = GG(E, F, G, i) + H + SS1 + W[i];


		D = C;
		C = LeftRotate(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = LeftRotate(F, 19);
		F = E;
		E = TT2 ^ LeftRotate(TT2, 9) ^ LeftRotate(TT2, 17);
	}
	context->intermediateHash[0] ^= A;
	context->intermediateHash[1] ^= B;
	context->intermediateHash[2] ^= C;
	context->intermediateHash[3] ^= D;
	context->intermediateHash[4] ^= E;
	context->intermediateHash[5] ^= F;
	context->intermediateHash[6] ^= G;
	context->intermediateHash[7] ^= H;
}

/*
* SM3运算的主体过程:
	message代表需要加密的消息字节串;
	messagelen是消息的字节数;
	digset表示返回的哈希值
*/
unsigned char* SM3::SM3Calc(const unsigned char* message,
	unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])
{
	SM3::SM3Context context;
	unsigned int i, remainder, bitLen;

	SM3_Init(&context);
	hash_result = messageLen / 64 + 1;
	//计算总块数
	remainder = messageLen % 64;
	if (remainder > 111) {
		hash_result += 1;
		//mod64之后如果大于111，说明超出了4KB，我们需要额外一块进行消息填充
		//总块数还要+1
	}
	//对前面的消息分组进行处理 
	for (i = 0; i < messageLen / 64; i++)
	{
		memcpy(context.messageBlock, message + i * 64, 64);
		Rate_of_hash = i + 1;
		//每处理一个512bit的消息块，进度就+1
		SM3_dealwith_MessageBlock(&context);
	}

	//填充消息分组，并处理 
	bitLen = messageLen * 8;
	if (IsLittleEndian())
		ReverseWord(&bitLen);
	memcpy(context.messageBlock, message + i * 64, remainder);
	context.messageBlock[remainder] = 0x80;
	//添加bit‘0x1000 0000’到末尾
	if (remainder <= 111)
	{
		//长度按照大端法占8个字节，只考虑长度在 2^32 - 1(bit)以内的情况，
		//故将高 4 个字节赋为 0 
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		Rate_of_hash += 1;//计算最后一个短块
		SM3_dealwith_MessageBlock(&context);
	}
	else
	{
		memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
		hash_rate += 1;
		//计算我额外添加的短块
		SM3_dealwith_MessageBlock(&context);
		//长度按照大端法占8个字节，只考虑长度在 2^32 - 1(bit)以内的情况，
		//故将高 4 个字节赋为 0 
		memset(context.messageBlock, 0, 64 - 4);
		memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
		Rate_of_hash += 1;
		//计算最后一个短块
		SM3_dealwith_MessageBlock(&context);
	}
	if (IsLittleEndian())
		for (i = 0; i < 8; i++)
			ReverseWord(context.intermediateHash + i);
	memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);
	return digest;
}

/*
* call_hash_sm3函数
	输入参数：文件地址字符串
	输出：向量vector<unit32_t> hash_result(32)
*/
std::vector<uint32_t> SM3::call_hash_sm3(char* filepath)
{
	std::vector<uint32_t> hash_result(32, 0);
	std::ifstream infile;
	uint32_t FILESIZE = 0;
	//进行文件操作，将该文件作为文本数据待加密
	unsigned char* buffer = new unsigned char[MAXSIZE];
	unsigned char hash_output[32];
	struct _stat info;
	_stat(filepath, &info);
	FILESIZE = info.st_size;
	infile.open(filepath, std::ifstream::binary);
	infile >> buffer;

	auto start = std::chrono::high_resolution_clock::now();
	SM3::SM3Calc(buffer, FILESIZE, hash_output);
	auto end = std::chrono::high_resolution_clock::now();
	// 以毫秒为单位，返回所用时间
	std::cout << "in millisecond time:";
	std::chrono::duration<double, std::ratio<1, 1000>> diff = end - start;
	std::cout << "Time is " << diff.count() << " ms\n";
	hash_result.assign(&hash_output[0], &hash_output[32]);
	delete[]buffer;
	return hash_result;
}

//对当前的哈希进度进行计算与反馈
double progress() {
	return (double(Rate_of_hash) / hash_result);
}

//创建固定大小的文件
void CreatTxt(char* pathName, int length)//创建txt文件
{
	ofstream fout(pathName);
	char char_list[] = "abcdefghijklmnopqrstuvwxyz";
	int n = 26;
	if (fout) { 
		for (int i = 0; i < length; i++)
		{
			fout << char_list[rand() % n]; 
			// 使用和输出流同样的方式进行写入
		}

		fout.close();  
		// 执行完操作后关闭文件句柄，
		//一定要写这一句，否则下次运行的时候会出现问题
	}
}
int main() {
	char filepath[] = "test.txt";
	CreatTxt(filepath, MAX_NUM);
	std::vector<uint32_t> hash_result;
	hash_result = SM3::call_hash_sm3(filepath);
	for (int i = 0; i < 32; i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << hash_result[i];
		if (((i + 1) % 4) == 0) std::cout << " ";
	}
	std::cout << std::endl;
	double rate = progress();
	printf("\n当前进度: %f", rate);
	return 0;
}
