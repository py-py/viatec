import errno
import logging
import os
import socket
import stat
import sys

from ptftplib import notify
from ptftplib import proto
from ptftplib import state
from ptftplib.tftpserver import TFTPServer
from ptftplib.tftpserver import TFTPServerConfigurationError
from ptftplib.tftpserver import TFTPServerHandler
from ptftplib.tftpserver import get_max_udp_datagram_size

try:
    import SocketServer as socketserver  # Py2
except ImportError:
    import socketserver  # Py3

l = notify.getLogger("tftpd")

_PTFTPD_SERVER_NAME = "pFTPd"
_PTFTPD_DEFAULT_PORT = 69


class ViatecTFTPServerHandler(TFTPServerHandler):
    def serveRRQ(self, op, request):
        try:
            filename, mode, opts = proto.TFTPHelper.parseRRQ(request)
        except SyntaxError:
            return None
        else:
            with open("log.txt", "a") as file:
                file.write(filename)
                file.write("\n")

        peer_state = state.TFTPState(
            self.client_address,
            op,
            self.server.root,
            filename,
            mode,
            not self.server.strict_rfc1350,
        )

        if not peer_state.filepath.startswith(self.server.root):
            peer_state.state = state.STATE_ERROR
            peer_state.error = proto.ERROR_ACCESS_VIOLATION

            l.warning(
                "Out-of-jail path requested: %s!" % filename,
                extra=peer_state.extra(notify.TRANSFER_FAILED),
            )
            return self.finish_state(peer_state)

        try:
            peer_state.file = open(peer_state.filepath, "rb")
            peer_state.filesize = os.stat(peer_state.filepath)[stat.ST_SIZE]
            peer_state.packetnum = 0
            peer_state.state = state.STATE_SEND

            l.info(
                "Serving file %s to host %s..." % (filename, self.client_address[0]),
                extra=peer_state.extra(notify.TRANSFER_STARTED),
            )

            # Only set options if not running in RFC1350 compliance mode
            # and when option were received.
            if not self.server.strict_rfc1350 and len(opts):
                opts = proto.TFTPHelper.parse_options(opts)
                if opts:
                    blksize = opts[proto.TFTP_OPTION_BLKSIZE]
                    windowsize = opts[proto.TFTP_OPTION_WINDOWSIZE]
                    max_window_size = int(
                        get_max_udp_datagram_size() / proto.TFTPHelper.get_data_size(blksize)
                    )
                    if windowsize > max_window_size:
                        l.info("Restricting window size to %d to fit UDP." % max_window_size)
                        opts[proto.TFTP_OPTION_WINDOWSIZE] = max_window_size

                    # HOOK: this is where we should check that we accept
                    # the options requested by the client.

                    peer_state.state = state.STATE_SEND_OACK
                    peer_state.set_opts(opts)
                else:
                    peer_state.file.close()
                    peer_state.state = state.STATE_ERROR
                    peer_state.error = proto.ERROR_OPTION_NEGOCIATION

        except IOError as e:
            peer_state.state = state.STATE_ERROR

            if e.errno == errno.ENOENT:
                peer_state.error = proto.ERROR_FILE_NOT_FOUND
                l.warning(
                    "Client requested non-existent file %s" % filename,
                    extra=peer_state.extra(notify.TRANSFER_FAILED),
                )
            elif e.errno == errno.EACCES or e.errno == errno.EPERM:
                peer_state.error = proto.ERROR_ACCESS_VIOLATION
                l.error(
                    "Client requested inaccessible file %s" % filename,
                    extra=peer_state.extra(notify.TRANSFER_FAILED),
                )
            else:
                peer_state.error = proto.ERROR_UNDEF
                l.error(
                    "Unknown error while accessing file %s" % filename,
                    extra=peer_state.extra(notify.TRANSFER_FAILED),
                )

        return self.finish_state(peer_state)


class ViatecTFTPServer(TFTPServer):
    def __init__(self, *args, **kwargs):
        super(ViatecTFTPServer, self).__init__(*args, **kwargs)
        self.server.server_close()
        self.server = socketserver.UDPServer((self.ip, self.port), ViatecTFTPServerHandler)
        self.server.root = self.root
        self.server.strict_rfc1350 = self.strict_rfc1350
        self.server.clients = self.client_registry


def main():
    import optparse

    usage = "Usage: %prog [options] <iface> <TFTP root>"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option(
        "-r",
        "--rfc1350",
        dest="strict_rfc1350",
        action="store_true",
        default=False,
        help="Run in strict RFC1350 compliance mode, " "with no extensions",
    )
    parser.add_option(
        "-p",
        "--port",
        dest="port",
        action="store",
        type="int",
        default=_PTFTPD_DEFAULT_PORT,
        metavar="PORT",
        help="Listen for TFTP requests on PORT",
    )
    parser.add_option(
        "-v",
        "--verbose",
        dest="loglevel",
        action="store_const",
        const=logging.INFO,
        help="Output information messages",
        default=logging.WARNING,
    )
    parser.add_option(
        "-D",
        "--debug",
        dest="loglevel",
        action="store_const",
        const=logging.DEBUG,
        help="Output debugging information",
    )

    (options, args) = parser.parse_args()
    if len(args) != 2:
        parser.print_help()
        return 1

    iface = args[0]
    root = os.path.abspath(args[1])

    # Setup notification logging
    notify.StreamEngine.install(
        l, stream=sys.stdout, loglevel=options.loglevel, fmt="%(levelname)s(%(name)s): %(message)s"
    )

    try:
        server = ViatecTFTPServer(iface, root, options.port, options.strict_rfc1350)
        server.serve_forever()
    except TFTPServerConfigurationError as e:
        sys.stderr.write("TFTP server configuration error: %s!" % e.args)
        return 1
    except socket.error as e:
        sys.stderr.write(
            "Error creating a listening socket on port %d: "
            "%s (%s).\n" % (options.port, e.args[1], errno.errorcode[e.args[0]])
        )
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
