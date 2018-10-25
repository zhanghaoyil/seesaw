# Seesaw

基于Netlink Socket的进程监控，主动检测进程打开FD，发现并处理反弹Shell行为。

### 思路

1）监听Netlink Socket，实时获取进程EXEC事件。

2）检查进程启动打开的FD，如果为Shell进程，打开了Socket而未使用/dev/tty、/dev/pts/n、/dev/ptmx等终端，则确认为反弹Shell。

3）保留必要证据后杀掉异常Shell进程。

### 系统兼容性

所有内核支持Netlink通信机制的操作系统。

### Dependency

依赖于https://github.com/dbrandt/proc_events项目，用于监听Netlink Socket。