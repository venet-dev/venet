~~~
assiduus@assiduus:~$ cat /proc/sys/net/ipv4/ip_forward
1*
assiduus@assiduus:~$
~~~
~~~
assiduus@assiduus:~$ gcc venet.c -o venet -lpcap
assiduus@assiduus:~$ sudo ./venet -e
10.10.10.14
10.10.10.20
10.10.10.21
10.10.10.48
10.10.10.52
10.10.10.56
10.10.10.57

The traffic between the default gateway and these devices runs through this computer...
~~~

\* **If this is set to 0 then all active devices on your LAN (except for the device venet is running on) will be unable to connect to the Internet.**
