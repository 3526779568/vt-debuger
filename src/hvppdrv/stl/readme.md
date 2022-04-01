#ifdef _KERNEL_MODE
#define _RAISE(x)	(x)
#define _RERAISE

#define _THROW0()
#define _THROW1(x)
#define _THROW(x, y)	x(y)
#endif // _KERNEL_MODE


上面代码放入exception文件或者替换我给的exception文件