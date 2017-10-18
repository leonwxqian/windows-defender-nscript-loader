# windows-defender-nscript-loader

**Intro**
A exe loader that can load NScript evaluation engine of Windows Defender/Microsft Security Essential.

You can send your javascript like script to this engine and fuzz NScript by yourself.

Project was (mostly) based on Tavis Ormandy(taviso)'s "Porting Windows Dynamic Link Libraries to Linux" (https://github.com/taviso/loadlibrary)
 
绝大多数代码都是基于Tavis大神的Linux下加载MSE DLL的工程，对日志记录等做了修改以让工程可以顺利地在Windows系统上跑起来。采用和该工程同样的协议GPLv2。
 
**Usage**

a) You **MUST** have a mpengine.dll from Windows Defender / MSE and put it under engine/mpengine.dll. Tested version is: 1.1.13804.0. (No download is proved here, you need to find this file by yourself.)

a）你**必须**先找到一个WD、MSE中所包含的mpengeine.dll文件并把它放到engine/mpengine.dll下。因为这个文件是微软的商业文件，这里不能提供下载，请自行查找，微软的网站上应该是能找的。
 
b) Compile the project with Visual Studio 2013.
 
b）使用VS2013 Update 4编译该工程。
 
c) Run the program.

c) 执行编译后的程序即可。
 
**License**
GPLv2
