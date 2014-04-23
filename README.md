pyirccat
========

### What?

pyirccat is a self contained <a href="https://github.com/RJ/irccat">irccat</a> clone written in Python. It was primarily developed for use at <a href="http://www.lovestruck.com/">Lovestruck.com</a>. Pull requests welcome!

### Why?

First, irccat doesn't support SSL enabled IRC servers, which if your IRC servers are SSL only, is a bit of a problem. Second, other irccat clones usually have some dependency on a big external IRC/networking library (twisted, various others) and I just wanted something simple and lightweight which is trivially installed. pyirccat's only external dependency is pyOpenSSL (which is fair enough, right?)

### How?

pyirccat listens on a specific ip and port and writes incoming data back to an irc channel. This is useful for sending various things (logs, whatever) to IRC from shell scripts or whatever else. As previously mentioned, it supports plain and SSL enabled IRC servers, and password protected IRC servers as well.


```bash
> python pyirccat.py
usage: pyirccat.py [-h] -s HOST [-p PORT] [--password PASSWORD] [-n NICKNAME]
                   -c CHANNEL -ba BIND_ADDR -bp BIND_PORT [--ssl] [-v]
```

Example:

```bash
> python pyirccat.py -s irc.freenode.net -p 6667 -n mybotnickname -c mychannel -ba 0.0.0.0 -bp 4444
```

then send some data to it (telnet, netcat, whatever - examples shown use netcat)

```bash
> echo "Hello World" | netcat -q0 localhost 4444
> tail -f /var/log/www/error.log | netcat localhost 4444
```

... the output will go directly to the channel you've specified when running pyirccat.py!

### When?

<img src="http://i.imgur.com/G2lAe1I.jpg">
