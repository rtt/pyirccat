# encoding: utf8
import argparse
from OpenSSL import SSL
import socket
import re
from time import sleep
import threading
from Queue import Queue

# todo: upgrde to threaded server sockets
# todo: signals to process to abort threads

def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    print 'Got certificate: %s' % cert.get_subject()
    return ok


class BindException(Exception):
    pass


class IRCClient(object):

    def __init__(self, host, port, channel, nick, ssl_mode=False, password=None):
        self.host = host
        self.port = port
        self.channel = channel
        self.nick = nick
        self.ssl_mode = ssl_mode
        self.password = password

    def __repr__(self):
        return '<IRCClient(%s:%s(%s) #%s nick=%s)>' % (
            self.host, self.port,
            '(SSL)' if self.ssl_mode else '(Plain)',
            self.channel, self.nick,
        )

    def _send(self, msg):
        sleep(0.2)
        print '> %s' % msg
        self._s.send(msg + '\n')

    def received(self, msg):
        print '< %s' % msg.strip()

    def privmsg(self, channel, msg):
        self._send('PRIVMSG #%s :%s' % (channel, msg))

    def join(self, channel):
        self._send('JOIN #%s' % self.channel)

    def quit(self, msg=None):
        q = 'QUIT' if not msg else 'QUIT :%s' % (msg,)
        self._send(q)

    def connect(self):
        '''Connect to irc server'''

        if self.ssl_mode:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            ctx.set_verify(SSL.VERIFY_PEER, verify_cb) # Demand a certificate
            self._s = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        else:
            self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.connect((self.host, self.port))

        if self.password is not None:
            self._send('PASS %s' % self.password)

        self._send('NICK %s' % self.nick)
        self._send('USER %s 8 * :foobar' % self.nick)

        while True:
            # get data
            d = self._s.recv(2048)

            # NERP
            if not d:
                break

            for l in d.strip().split('\n'):
                self.received(l)

            if 'End of MOTD' in d:
                self.join(self.channel)
                self.privmsg(self.channel, 'hi there...')

            if 'PING' in d:
               received = d.strip()
               pong = received.split(':')[1]
               self._send('PONG :%s' % pong)

        print '[Done]'

    def parse_message(self, raw):
        r = re.match(r'#([\w\d_\-]+)\s{1}(.*)', raw)
        if r is None:
            return None

        channel, msg = r.groups()
        return channel, msg

    def send(self, d):
        parsed = self.parse_message(d)
        if parsed is not None:
            # message was valid
            channel, msg = parsed
            print 'sending "%s" to #%s' % (msg, channel)
            self.privmsg(channel, msg)
        else:
            print 'invalid msg'


class Listener(object):
    '''Listener object which listens on a host and port, and sends messages through
    to a provided "conduit"
    '''

    def __init__(self, bind_addr, bind_port, queue):
        self.bind_addr = bind_addr
        self.bind_port = bind_port
        self.queue = queue

    def __repr__(self):
        return '<Listener(%s:%s)>' % (self.bind_addr, self.bind_port)

    def __enter__(self):
        if self._s:
            self._s.close()

    def __exit__(self):
        self._s.close()

    def close(self):
        if self._s:
            self._s.close()

    def listen(self):

        try:
            self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            try:
                self._s.bind((self.bind_addr, self.bind_port))
            except socket.error:
                em = 'Could not bind to host %s:%s' % (self.bind_addr, self.bind_port)
                if self.bind_port < 1024:
                    em = '%s (port < 1024, privilege error?)' % em

                raise BindException(em)

            self._s.listen(1)
            conn, addr = self._s.accept()
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                # now pipe this to our receiver
                print 'sending to conduit >>>'
                self.queue.put(data)
        except KeyboardInterrupt:
            self.conduit.quit()
            print 'Closing listener connection'
            self._s.close()
            print 'Reraising...'
            raise KeyboardInterrupt
        except:
            raise


def cli_args():
    parser = argparse.ArgumentParser(description='pyirccat - cat to irc')
    parser.add_argument('-s', '--server', dest='host', required=True, type=str, help='IRC Server hostname')
    parser.add_argument('-p', '--port', dest='port', default=6667, type=int, help='IRC Server port')
    parser.add_argument('--password', dest='password', type=str, help='IRC server password')
    parser.add_argument('-n', '--nickname', dest='nickname', default='pyirccat', type=str, help='Nickname of bot')
    parser.add_argument('-c', '--channel', dest='channel', required=True, type=str, help='Channel to join, without # prefix')
    parser.add_argument('-ba', '--bind-addr', dest='bind_addr', required=True, type=str, help='IP to bind to')
    parser.add_argument('-bp', '--bind-port', dest='bind_port', required=True, type=int, help='Port to bind to')
    parser.add_argument('--ssl', dest='ssl', action='store_true', help='Join server via SSL')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Noisy mode')

    return parser


class IRCClientWorker(threading.Thread):
    def __init__(self, host, port, channel, nickname, queue, ssl_mode=False, password=None):
        threading.Thread.__init__(self)

        self.host = host
        self.port = port
        self.channel = channel
        self.nickname = nickname
        self.ssl_mode = ssl_mode
        self.password = password
        self.queue = queue

    def run(self):
        irc_client = IRCClient(
            self.host, self.port, self.channel,
            self.nickname, self.ssl_mode, self.password,
        )

        print irc_client

        def irc_connect():
            irc_client.connect()

        t = threading.Thread(target=irc_connect)
        t.daemon = True
        t.start()

        while True:
            print 'sending items...'
            item = self.queue.get()
            irc_client.send(item)



class ListenerWorker(threading.Thread):
    def __init__(self, addr, port, queue):
        threading.Thread.__init__(self)

        self.addr = addr
        self.port = port
        self.queue = queue

    def run(self):
        socket_listener = Listener(self.addr, self.port, self.queue)
        print socket_listener
        socket_listener.listen()


if __name__ == '__main__':
    parser = cli_args().parse_args()

    if parser.verbose:
        print 'verbose mode'

    q = Queue()

    t_irc = IRCClientWorker(parser.host, parser.port, parser.channel,
        parser.nickname, q, parser.ssl, parser.password
    )

    t_listener = ListenerWorker(parser.bind_addr, parser.bind_port, q)

    t_irc.start()
    t_listener.start()

    # and sit and wait...
    t_irc.join()
    t_listener.join()
