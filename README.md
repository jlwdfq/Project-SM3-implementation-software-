# Project-SM3-implementation-software-
在软件上尽最大努力实现SM3，使得SM3的加密速度尽可能的快 确保你理解所写的每一行（不要复制粘贴）通过更快的运行获得更高的分数

整个SM3算法的执行过程可以概括成四个步骤：消息填充、消息扩展、迭代压缩、输出结果。下面分块进行详细说明：

**国密算法SM3方案概述**

SM3密码杂凑算法是中国国家密码管理局2010年公布的中国商用密码杂凑算法标准。具体算法标准原始文本参见参考文献【1】。该算法于2012年发布为密码行业标准(GM/T 0004-2012)，2016年发布为国家密码杂凑算法标准(GB/T 32905-2016)。

SM3适用于商用密码应用中的数字签名和验证，是在[SHA-256]基础上改进实现的一种算法，其安全性可以认为与SHA-256类似。在进行杂凑过程中SM3和MD5的迭代过程类似，也采用Merkle-Damgard结构。消息分组长度为512位，hash值计算出的长度为256位。

**一.消息填充**

SM3的消息扩展步骤是以512位的数据分组作为输入的。因此，我们需要在一开始就把数据长度填充至512位的倍数。数据填充规则和MD5一样，具体步骤如下：

1、先填充一个“1”，后面加上k个“0”。其中k是满足(n+1+k) mod 512 = 448的最小正整数（512-64=448 bit 位）

2、追加64位的数据长度（bit为单位，大端序存放1。观察国家密码管理局关于发布《SM3密码杂凑算法》公告的原文附录A运算示例可以推知。）

消息填充示例：

![图片](https://user-images.githubusercontent.com/107350922/180603855-56f80ebe-d450-4814-82ff-db22e83212ed.png)

**二.消息扩展**

SM3的迭代压缩步骤没有直接使用数据分组进行运算，而是使用这个步骤产生的132个消息字。（一个消息字的长度为32位/4个字节/8个16进制数字）概括来说，先将一个512位数据分组划分为16个消息字，并且作为生成的132个消息字的前16个。再用这16个消息字递推生成剩余的116个消息

在最终得到的132个消息字中，前68个消息字构成数列 {Wj}，后64个消息字构成数列 {Wj'}，其中下标j从0开始计数。

**参考资料：**

【1】国家密码管理局关于发布《SM3密码杂凑算法》公告：http://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml
