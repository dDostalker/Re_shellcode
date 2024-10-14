# Re_shellcode

![Reshellcode.png](https://github.com/dDostalker/Re_shellcode/blob/main/.picture/Reshellcode.png?raw=true)



> **！！！项目目前只完成框架，缺少大量汇编指令和api的功能，目前只能对msf生成32/64位linux进行分析** 
>
> 

Reshellcode是由rust构建的shellcode模拟运行动态分析器，通过模拟32/64位处理器、内存和基本Windows API/Linux系统调用运行环境来虚拟执行Shellcode以分析其行为。

### 实现原理

Shellcode为了实现特定的功能必须通过调用系统API来完成。Re_shellcode通过模拟执行以多个API来探测shellcode的行为。例如，创建文件和访问网络这些危险的API并没有真正的在本机执行，而是通过传回虚假的返回值来欺骗shellcode让其平稳运行。

### 优势

- 跨平台开源

  同时支持Unix和Windows系统，对有系统洁癖的同学来说可以放心在Unix下搭建环境“调戏”shellcode

- 文档数据捕获

  可以对多种语言的书写格式进行捕获加载

- 其他重要功能

  包括反汇编、内存监视、简单调试Shell、一键梭哈

- 支持不只x86架构

### 使用方法

```shell
# 	带*的为唯一参数，带!的为正常运行不可遗漏参数
    --help 		-h	查看帮助*
    --version 	-v	查看版本*
    --file		-f	选择单文件导入程序 后跟文件路径!
    --arch		-a	设置架构
    --debug		-b	调试模式
```

### 示例

```powershell
.\Reshellcode.exe -f ".\shellcode_linux_x86\shellcode-vbs.txt" -a x86 
```

![Reshellcode1.png](https://github.com/dDostalker/pictures/blob/main/Reshellcode1.png?raw=true)

![Reshellcode2.png](https://github.com/dDostalker/pictures/blob/main/Reshellcode2.png?raw=true)

![Reshellcode3.png](https://github.com/dDostalker/pictures/blob/main/Reshellcode3.png?raw=true)
