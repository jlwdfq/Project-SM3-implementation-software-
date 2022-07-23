#define SM3_HASH_SIZE 32
//实现思路为先将SM3 hash标准输入输出
//作为一个单独的变量类型写为结构体的形式
//为方便后续的调用
namespace SM3 {
	//hash vector 共有多少字节
	typedef struct SM3Context {
		unsigned int intermediateHash[SM3_HASH_SIZE / 4];
		unsigned char messageBlock[64];
	//在SM3方案介绍中我们知道512位的数据块作为输入，是进行hash的对象
	} SM3Context;

	unsigned char* SM3Calc(const unsigned char* message,
		unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE]);

	std::vector<uint32_t> call_hash_sm3(char* filepath);

	double progress();
}