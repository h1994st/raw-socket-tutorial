raw socket tutorial
===================
All the source files in this repository are based on Mac OS X platform, and are compiled succesfully.

For any source file in this repository:

```bash
$ gcc -o <filename> <source file>
```

Then

```bash
$ sudo ./<filename> [arguments...]
```

Most of the programs using raw socket require root permission.

You can capture packets via [Wireshark](https://www.wireshark.org/).

## References

- [ICMP ping flood code using sockets in C – Linux](http://www.binarytides.com/icmp-ping-flood-code-sockets-c-linux/)
