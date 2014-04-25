# encoding: utf8
import argparse
from Queue import Queue
import re
import socket
import sys
import threading
from time import sleep
from os import getpid

# ext. dependencies
from OpenSSL import SSL


def verify_cb(conn, cert, errnum, depth, ok):
    return ok


class BindException(Exception):
    '''Thrown when we cant listen on a given ip:port'''
    pass


class IRCClient(object):
    '''Simple IRC client - supports PRIVMSG, JOIN and QUIT commands'''

    def __init__(self, host, port, channel, nick, ssl_mode=False, ssl_no_verify=False, password=None):
        self.host = host
        self.port = port
        self.channel = channel
        self.nick = nick
        self.ssl_mode = ssl_mode
        self.ssl_no_verify = ssl_no_verify
        self.password = password

        self._connected = False
        self.realname = 'pyirccat'

    def __repr__(self):
        return '<%s(%s:%s(%s) channel=#%s nick=%s)>' % (
            self.__class__.__name__, self.host, self.port,
            '(SSL, %s)' % ('non-verified' if self.ssl_no_verify else 'verified') if self.ssl_mode else '(Plain)',
            self.channel, self.nick,
        )

    def _send(self, msg, delay=True):
        '''Internal send method to send a command to the irc server connection'''
        if not self._connected:
            return

        # we delay most messages in some vein attempt
        # not to flood an ircd
        if delay:
            sleep(0.2)

        print '> %s' % msg
        self._s.send('%s\n' % (msg,))

    def connect(self):
        '''Connect to irc server'''

        if self.ssl_mode:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            if not self.ssl_no_verify:
                ctx.set_verify(SSL.VERIFY_PEER, verify_cb)
            self._s = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        else:
            self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # note; calling code is expected to deal with a thrown socket.error
        self._s.connect((self.host, self.port))
        self._connected = True

        if self.password is not None:
            self._send('PASS %s' % self.password)

        # send nick and user commands, then join the channel and announce presence
        self._send('NICK %s' % self.nick)
        self._send('USER %s 8 * :%s' % (self.nick, self.realname))

        self.join(self.channel)
        self.privmsg(self.channel, 'Bot active')

    def interact(self):
        '''
        Interact indefinitely with the irc server after connection
        Currently essentially all this does is report data received from the server
        and replies to ping requests
        '''

        while self._connected:
            try:
                d = self._s.recv(2048)
            except:
                break
            else:
                if not d:
                    break

            for l in d.strip().split('\n'):
                self.received(l)

            if d.startswith('PING :'):
                try:
                    self._send('PONG :%s' % (d.strip().split(':')[1],))
                except:
                    print '[error PONG]'

    def parse_message(self, raw):
        '''Parses a message to work out if it was channel prefixed or not '''
        if not raw:
            return None

        r = re.match(r'#([\w\d_\-]+)\s{1}(.*)', raw)
        if r is None:
            return self.channel, raw

        # we wanted it sent to some other channel
        channel, msg = r.groups()
        return channel, msg

    def received(self, msg):
        print '< %s' % msg.strip()

    def send(self, d):
        '''Sends a message to a channel
        Expected format: "#channel message here"
        '''
        parsed = self.parse_message(d)

        if parsed is not None:
            # message was valid
            channel, msg = parsed
            # send message to channel
            self.privmsg(channel, msg)

    # IRC commands
    # see RFC2812: https://tools.ietf.org/html/rfc2812
    def privmsg(self, channel, msg):
        self._send('PRIVMSG #%s :%s' % (channel, msg))

    def join(self, channel):
        self._send('JOIN #%s' % self.channel)

    def quit(self, msg=None):
        self._connected = False
        self._send('QUIT' if not msg else 'QUIT :%s' % (msg,))
        self._s.close()


class Listener(object):
    '''Listener which listens on a host and port for messages and shoves
    said messages into a queue which the irc client consumes
    '''

    def __init__(self, bind_addr, bind_port, queue, backlog=4):
        self.bind_addr = bind_addr
        self.bind_port = bind_port
        self.queue = queue
        self.backlog = backlog

    def __repr__(self):
        return '<%s(%s:%s)>' % (self.__class__.__name__, self.bind_addr, self.bind_port)


    def close(self):
        if hasattr(self, '_s'):
            self._s.close()

    def listen(self):

        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self._s.bind((self.bind_addr, self.bind_port))
        except socket.error:
            em = 'Could not bind to host %s:%s' % (self.bind_addr, self.bind_port)

            if self.bind_port < 1024:
                em = '%s (port < 1024, privilege error?)' % em

            raise BindException(em)

        self._s.listen(self.backlog)

        while True:
            conn, addr = self._s.accept()

            def h_cnx():
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break

                    # bump message onto queue
                    self.queue.put(data)
                    break

                conn.close()

            t = threading.Thread(target=h_cnx)
            t.start()


class IRCClientWorker(threading.Thread):

    def __init__(self, host, port, channel, nickname, queue, ssl_mode=False, ssl_verify=True, password=None):
        threading.Thread.__init__(self)

        self.host = host
        self.port = port
        self.channel = channel
        self.nickname = nickname
        self.ssl_mode = ssl_mode
        self.ssl_verify = ssl_verify
        self.password = password
        self.queue = queue

        self._stop = threading.Event()

        self.process = IRCClient(
            self.host, self.port, self.channel,
            self.nickname, self.ssl_mode, self.ssl_verify, self.password,
        )

    def stop(self):
        self.process.quit()
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

    def run(self):
        # connect to server
        try:
            self.process.connect()
        except socket.error:
            return

        # spin the interaction off into a thread
        def irc_interact():
            self.process.interact()

        t = threading.Thread(target=irc_interact)
        t.daemon = True
        t.start()

        # send items in the queue off to be processed
        while True and not self.stopped():
            item = self.queue.get()
            if item is None:
                # none is a signal to quit
                break
            self.process.send(item)


class ListenerWorker(threading.Thread):

    def __init__(self, addr, port, queue):
        threading.Thread.__init__(self)

        self.addr = addr
        self.port = port
        self.queue = queue

        self._stop = threading.Event()

        self.process = Listener(self.addr, self.port, self.queue)

    def stop(self):
        self.process.close()
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

    def run(self):
        while True and not self.stopped():
            try:
                self.process.listen()
            except BindException as e:
                print 'Error: %s' % (e,)
                self.stop()
                break


class MainWorker(threading.Thread):

    def __init__(self, parser):
        threading.Thread.__init__(self)
        self.parser = parser
        self._stop = threading.Event()
        self.threads = []

    def stop(self):
        self._stop.set()
        for t in self.threads:
            t.stop()

    def stopped(self):
        return self._stop.isSet()

    def run(self):

        q = Queue()

        t_irc = IRCClientWorker(
            self.parser.host, self.parser.port, self.parser.channel,
            self.parser.nickname, q, self.parser.ssl, self.parser.ssl_no_verify,
            self.parser.password
        )

        t_listener = ListenerWorker(self.parser.bind_addr, self.parser.bind_port, q)

        self.threads.append(t_irc)
        self.threads.append(t_listener)

        t_irc.daemon = True
        t_listener.daemon = True

        # start them
        t_irc.start()
        t_listener.start()

        while True:
            # if either thread quits, stop everything
            sleep(0.25)
            if t_listener.stopped() or t_irc.stopped():
                self.stop()

def cli_args():
    '''Returns a prepared ArgumentParser'''

    parser = argparse.ArgumentParser(description='pyirccat - cat to irc')
    parser.add_argument('-s', '--server', dest='host', required=True, type=str,
        help='IRC Server hostname')
    parser.add_argument('-p', '--port', dest='port', default=6667, type=int,
        help='IRC Server port')
    parser.add_argument('--password', dest='password', type=str, help='IRC server password')
    parser.add_argument('-n', '--nickname', dest='nickname', default='pyirccat', type=str,
        help='Nickname of bot')
    parser.add_argument('-c', '--channel', dest='channel', required=True, type=str,
        help='Channel to join, without # prefix')
    parser.add_argument('-ba', '--bind-addr', dest='bind_addr', required=True, type=str,
        help='IP to bind to')
    parser.add_argument('-bp', '--bind-port', dest='bind_port', required=True, type=int,
        help='Port to bind to')
    parser.add_argument('--ssl', dest='ssl', action='store_true', help='Join server via SSL')
    parser.add_argument('--ssl-no-verify', dest='ssl_no_verify', action='store_true',
        help='Disable SSL cert verification')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Noisy mode')

    return parser


if __name__ == '__main__':

    parser = cli_args().parse_args()

    main_worker = MainWorker(parser)
    main_worker.daemon = True
    main_worker.start()

    while not main_worker.stopped():
        try:
            sleep(0.1)
            main_worker.join(1.0)
        except KeyboardInterrupt:
            main_worker.stop()
            sys.exit(0)

    # we're done.
    print 'Finished!'
