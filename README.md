# 根据 [Milo Yip 的 JSON 库教程](https://github.com/miloyip/json-tutorial) 制作的JSON解析库

* ValyrianSteel
* 2016/10/19
* leptjson 是一个手写的递归下降解析器（recursive descent parser）。lept取自lepton（轻子），意为轻量级。由于 JSON 语法特别简单，我们不需要写分词器（tokenizer），只需检测下一个字符，便可以知道它是哪种类型的值，然后调用相关的分析函数。

## JSON 库的特性如下：

* 符合标准的 JSON 解析器和生成器
* 手写的递归下降解析器（recursive descent parser）
* 使用标准 C 语言（C89）
* 跨平台／编译器（如 Windows／Linux／OS X，vc／gcc／clang）
* 仅支持 UTF-8 JSON 文本
* 仅支持以 `double` 存储 JSON number 类型
* 解析器和生成器的代码合共少于 500 行

## 测试驱动开发（test driven development, TDD）
先写测试，再实现功能。  
1、加入一个测试。  
2、运行所有测试，新的测试应该会失败。  
3、编写实现代码。  
4、运行所有测试，若有测试失败回到3。  
5、重构代码。  
6、回到 1。  
* C 语言编程风格
* 数据结构
* API 设计

##  断言
断言（assertion）是 C 语言中常用的防御式编程方式，减少编程错误。最常用的是在函数开始的地方，检测所有参数。有时候也可以在调用函数后，检查上下文是否正确。  
C 语言的标准库含有 assert() 这个宏（需 #include ），提供断言功能。当程序以 release 配置编译时（定义了 NDEBUG 宏），assert() 不会做检测；而当在 debug 配置时（没定义 NDEBUG 宏），则会在运行时检测 assert(cond) 中的条件是否为真（非 0），断言失败会直接令程序崩溃。  

何时使用断言：  
* 如果那个错误是由于程序员错误编码所造成的（例如传入不合法的参数），那么应用断言；
* 如果那个错误是程序员无法避免，而是由运行时的环境所造成的，就要处理运行时错误（例如开启文件失败）。
* 不能把有副作用的代码放在assert()中。

* Unicode
* 浮点数
* Github、CMake、valgrind、Doxygen 等工具
