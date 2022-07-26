# Project-SM3-implementation-software-
在软件上尽最大努力实现SM3，使得SM3的加密速度尽可能的快 确保你理解所写的每一行（不要复制粘贴）通过更快的运行获得更高的分数

整个SM3算法的执行过程可以概括成四个步骤：消息填充、消息扩展、迭代压缩、输出结果。下面分块进行详细说明：

**国密算法SM3方案概述**

SM3密码杂凑算法是中国国家密码管理局2010年公布的中国商用密码杂凑算法标准。具体算法标准原始文本参见参考文献【1】。该算法于2012年发布为密码行业标准(GM/T 0004-2012)，2016年发布为国家密码杂凑算法标准(GB/T 32905-2016)。

SM3适用于商用密码应用中的数字签名和验证，是在[SHA-256]基础上改进实现的一种算法，其安全性可以认为与SHA-256类似。在进行杂凑过程中SM3和MD5的迭代过程类似，也采用Merkle-Damgard结构。消息分组长度为512位，hash值计算出的长度为256位。【4】

首先SM3是一种hash函数，那么首先其具有如下特性：

1. 对于任何一个给定的消息，它都很容易就能运算出散列数值。（多项式时间可计算）

2. 难以由一个已知的散列数值，去推算出原始的消息。（单向性，求逆困难，一般认为在多项式时间内只能以可忽略的概率计算出其逆）

3. 在不更动散列数值的前提下，修改消息内容是不可行的。（认证性）

4. 对于两个不同的消息，它不能给与相同的散列数值。（抗碰撞性）

**一.消息填充**
-
SM3的消息扩展步骤是以512位的数据分组作为输入的。因此，我们需要在一开始就把数据长度填充至512位的倍数。数据填充规则和MD5一样，具体步骤如下：

1、先填充一个“1”，后面加上k个“0”。其中k是满足(n+1+k) mod 512 = 448的最小正整数（512-64=448 bit 位）

2、追加64位的数据长度（bit为单位，大端序存放1。观察国家密码管理局关于发布《SM3密码杂凑算法》公告的原文附录A运算示例可以推知。）

消息填充示例：

![图片](https://user-images.githubusercontent.com/107350922/180603855-56f80ebe-d450-4814-82ff-db22e83212ed.png)【2】

**二.消息扩展**
-
SM3的迭代压缩步骤没有直接使用数据分组进行运算，而是使用这个步骤产生的132个消息字。（一个消息字的长度为32位/4个字节/8个16进制数字）概括来说，先将一个512位数据分组划分为16个消息字，并且作为生成的132个消息字的前16个。再用这16个消息字递推生成剩余的116个消息

在最终得到的132个消息字中，前68个消息字构成数列 {Wj}，后64个消息字构成数列 {Wj'}，其中下标j从0开始计数。

具体消息扩展运算过程如下图所示：

![图片](https://user-images.githubusercontent.com/107350922/180604058-71bd94a6-bcb4-440a-b4b9-059a823e6379.png)【3】


**三.迭代压缩**
-
在上文已经提过，SM3的迭代过程和MD5类似，也是Merkle-Damgard结构。但和MD5不同的是，SM3使用消息扩展得到的消息字进行运算。这个迭代过程可以用下图表示：

![图片](https://user-images.githubusercontent.com/107350922/180604106-ff7ba147-d264-4178-bde8-351c9e63f6c1.png)【3】

初值IV被放在A、B、C、D、E、F、G、H八个32位变量中，

其具体数值参见SM3公告【1】。整个算法中最核心、也最复杂的地方就在于压缩函数（compression）。压缩函数将这八个变量进行64轮相同的计算。

其中一轮的计算过程如下图所示：

![图片](https://user-images.githubusercontent.com/107350922/180604283-012df071-1f7d-4cea-a8d3-77e2a8ff55b6.png)【3】

图中不同的数据流向用不同颜色的箭头表示。

最后，再将计算完成的A、B、C、D、E、F、G、H和原来的A、B、C、D、E、F、G、H分别进行异或，就是压缩函数的输出。

这个输出再作为下一次调用压缩函数时的初值。进入递归函数，递归的终止条件是直到用完最后一组132个消息字为止。

**输出结果**

将上面第三步中计算出的A、B、C、D、E、F、G、H八个变量拼接输出，就是SM3算法的最终输出的杂凑值。


**四.代码实现思路**
-
SM3的每个部件的相关实现

**标准FF与GG部件相关的布尔运算的实现**

![图片](https://user-images.githubusercontent.com/107350922/180921044-0140290d-0c4d-46d0-883e-e6ea85f70d4c.png)

**P0/P1置换函数**

![图片](https://user-images.githubusercontent.com/107350922/180921174-d3240298-3c74-4748-8a40-d8f0e85a55cf.png)

**字节翻转操作**

在 SM3 算法中，string以大端格式存储所以在标准运算中，针对每个待加密的字符串应该进行翻转后再进行加密运算

![图片](https://user-images.githubusercontent.com/107350922/180921553-5d6f09af-2b03-4de7-a5a9-c8f498c9d586.png)

**消息填充**

将数据长度填充为512bit的倍数。长度按照大端法占用8个字节，只考虑2^32 - 1（单位：位）以内的长度，*所以分配高4个字节为 0。

![图片](https://user-images.githubusercontent.com/107350922/180921796-b8f25a13-08e6-48f2-a513-01f26de19a5d.png)

剩余部件如消息扩展，消息压缩等的详细代码实现操作，请参看SM3_Enc.cpp文件中相应部分，均已写明注释。

五.SM3算法部分优化方向
-
优化思路相关参考上传的SM3_Reference.pdf文件与参考资料【5】中的优化思路

**优化方向一：消息扩展的快速实现**

优化原理：

    优化前：计算前16个wi时，每个需要执行一次load和一个store，计算后52个wi时，每个需要执行5次load，1次store，6次XOR和1次rot；
    计算64个wi，每个wi需要执行2次load，1次store和1次rot。
    
    优化后：
    在计算前 12 个 wi+4 时，每个都需要执行一次加载和一次保存。 在计算最后52个wi+4时，每个需要进行5次load，1次store，6次XOR，4次rot；
    主要是减少计算和存储W'时的存取操作。 在测试中，优化也提高了算法的执行速度

优化实现：
在执行64轮压缩函数之前，只计算最初的四个词，其余的在每一轮压缩函数中计算。 Wi+4在压缩函数的第I轮生成，将w1'替换为wi^wi+4。

![图片](https://user-images.githubusercontent.com/107350922/180923528-7aef5f25-21ea-4b5a-bcc8-01a00b1888c7.png)

**优化方向二：预计算常数**

常数是预先计算和存储的。 这样可以避免对每个消息包进行不断的移位操作，优化后占用的存储空间也很小，只有256字节。 

![图片](https://user-images.githubusercontent.com/107350922/180923861-5df4640b-e711-4acf-a80f-73c88cc7d374.png)

**优化方向三：优化压缩函数中间变量的生成过程**

去除了不必要的赋值，减少了中间变量的数量。 方法3、4优化后，只更新了D、h、B、F，减少了赋值操作。压缩函数的结构进行了调整，大大减少了load和store的数量，而中间变量TT1和TT2的优化进一步减少了rot的数量。 

![图片](https://user-images.githubusercontent.com/107350922/180924370-1f099156-90bc-4f06-838f-f9034d35cc0a.png)


**优化方向四：对压缩函数进行结构性调整**

在每一轮压缩函数结束时，将执行一次循环右移。 将string循环向右移动可以改变每轮输入string的顺序，这个顺序变化会在4轮后恢复，代码实现如下

![图片](https://user-images.githubusercontent.com/107350922/180924074-ebd632ef-3ca1-471c-a32c-3e194577eecd.png)

运行结果截图
-

**参考资料：**
-
【1】国家密码管理局关于发布《SM3密码杂凑算法》公告：http://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml

【2】SM3密码杂凑算法原理简述： https://zhuanlan.zhihu.com/p/129692191

【3】SM3加密算法详解（2021-12-8）： https://blog.csdn.net/qq_40662424/article/details/121637732

【4】SM3百度百科： https://baike.baidu.com/item/SM3/4421797?fr=aladdin

【5】SM3密码杂凑算法--＞大文件做摘要优化： https://blog.csdn.net/oprim/article/details/124179928
