
安装trustzone虚拟环境，在optee/build目录下交叉编译
‵‵‵
make run


会出现qemu，normal，secure三个窗口
qemu窗口输入c运行环境

在normal窗口中/usr/bin目录下有optee_example内交叉编译好的应用程序，normal相当于一个操作系统，在里面可以创建文件

这里将需要加密的文件./key放在了usr/bin下

执行：
```
optee_TEEencrypt -e ./key RSA