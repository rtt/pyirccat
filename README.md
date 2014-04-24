pyirccat - python irccat
========

### What?

pyirccat is a self contained <a href="https://github.com/RJ/irccat">irccat</a> clone written in Python. It was primarily developed for use at <a href="http://www.lovestruck.com/">Lovestruck.com</a> which uses IRC extensively for logging and reporting various things from servers back to IRC. Pull requests, comments etc are welcome.

### Why?

First, irccat doesn't support SSL enabled IRC servers, which if your IRC servers are SSL only presents a bit of a problem. Second, other irccat clones usually have some dependency on a big external IRC/networking library (<a href="https://twistedmatrix.com/trac/">twisted</a>, <a href="http://python-irclib.sourceforge.net/">irclib</a> and various others) and I just wanted something simple and lightweight which is trivially installed. pyirccat's only external dependency is <a href="https://github.com/pyca/pyopenssl">pyOpenSSL</a> (which is fair enough, right?)

### How?

pyirccat listens on a specific ip and port and writes incoming data back to an irc channel. This is useful for sending various things (logs, whatever) to IRC from shell scripts or whatever else. As previously mentioned, it supports plain and SSL enabled IRC servers, and password protected IRC servers too.

```bash
> python pyirccat.py
usage: pyirccat.py [-h] -s HOST [-p PORT] [--password PASSWORD] [-n NICKNAME]
                   -c CHANNEL -ba BIND_ADDR -bp BIND_PORT [--ssl] [-v]

pyirccat - cat to irc

optional arguments:
  -h, --help            show this help message and exit
  -s HOST, --server HOST
                        IRC Server hostname
  -p PORT, --port PORT  IRC Server port
  --password PASSWORD   IRC server password
  -n NICKNAME, --nickname NICKNAME
                        Nickname of bot
  -c CHANNEL, --channel CHANNEL
                        Channel to join, without # prefix
  -ba BIND_ADDR, --bind-addr BIND_ADDR
                        IP to bind to
  -bp BIND_PORT, --bind-port BIND_PORT
                        Port to bind to
  --ssl                 Join server via SSL
  -v, --verbose         Noisy mode
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

You can also prefix output with an arbitary channel to send to, e.g. -

```bash
> echo "#someotherchannel foo" | netcat -q0 localhost 4444
```

(would send to #someotherchannel even if you invoked the bot with a channel other than #someotherchannel)


### When?

<img src="http://i.imgur.com/G2lAe1I.jpg">
