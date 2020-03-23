package com.fsck.k9.mail.protocols.socks;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Implements limited SOCKS5 proxy client functionality as specified in RFC 1928. A client object
 * uses a provided {@link InputStream} and {@link OutputStream} to communicate with a SOCKS5 proxy
 * server. Methods are provided to perform a SOCKS5 handshake and to request IPv4 or IPv6 proxy
 * connections to target systems via a specified hostname and port number. Authentication is not
 * implemented and the server must allow no-authentication access.
 */
public class Socks5Client {

    private InputStream in;
    private OutputStream out;

    private static final byte PROTOCOL_VERSION = 0x05;
    private static final byte AUTH_NONE = 0x00;
    private static final byte CMD_CONNECT = 0x01;
    private static final byte ADDR_TYPE_IPV4 = 0x01;
    private static final byte ADDR_TYPE_HOSTNAME = 0x03;
    private static final byte ADDR_TYPE_IPV6 = 0x04;
    private static final byte ERR_SUCCESS = 0x00;

    /**
     * Constructs a SOCKS5 client object which will communicate using the specified input and
     * output streams. No communication occurs until {@link #handshake()} is called.
     *
     * @param in The input stream from which to receive data from the SOCKS5 server.
     * @param out The output stream to which to transmit data to the SOCKS5 server.
     */
    public Socks5Client(InputStream in, OutputStream out) {

        if (in == null) {
            throw new IllegalArgumentException("SOCKS5: input stream is null");
        } else if (out == null) {
            throw new IllegalArgumentException("SOCKS5: output stream is null");
        }

        this.in = in;
        this.out = out;

    }

    /**
     * Performs a SOCKS5 protocol negotiation. This method must be called before any of the
     * connect functions are called.
     *
     * @throws IOException An I/O or SOCKS5 protocol error occurred.
     */
    public void handshake() throws IOException {

        out.write(new byte[] { PROTOCOL_VERSION, 1, AUTH_NONE});
        out.flush();

        byte[] reply = readExactly(2);

        if (reply[0] != PROTOCOL_VERSION) {
            throw new IOException("SOCKS5: unsupported server protocol version: " + reply[0]);
        } else if (reply[1] != AUTH_NONE) {
            throw new IOException("SOCKS5: unsupported authentication method: " + reply[1]);
        }

    }

    /**
     * Requests a SOCKS5 TCP proxy connection to a target specified by hostname and port number. A
     * successful {@link #handshake()} must occur prior to calling this method.
     *
     * @param hostname The hostname of the target to connect to.
     * @param port The port number of the target to connect to.
     *
     * @throws IOException An I/O or SOCKS5 protocol error occurred or the proxy connection
     *     failed.
     */
    public void connect(String hostname, int port) throws IOException {

        if (hostname == null) {
            throw new IllegalArgumentException("SOCKS5: hostname is null");
        } else if (hostname.length() > 255) {
            throw new IllegalArgumentException("SOCKS5: hostname is too long");
        } else if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException("SOCKS5: port number is invalid");
        }

        byte[] data = new byte[7 + hostname.length()];
        data[0] = PROTOCOL_VERSION;
        data[1] = CMD_CONNECT;
        data[2] = 0; // reserved
        data[3] = ADDR_TYPE_HOSTNAME;
        data[4] = (byte) hostname.length();
        data[5 + hostname.length()] = (byte) (port >> 8);
        data[6 + hostname.length()] = (byte) port;

        for (int i = 0; i < hostname.length(); ++i) {
            data[5 + i] = (byte) hostname.charAt(i);
        }

        out.write(data);
        out.flush();

        byte[] reply = readExactly(4);

        if (reply[0] != PROTOCOL_VERSION) {
            throw new IOException("SOCKS5: unsupported server protocol version: " + reply[0]);
        } else if (reply[1] != ERR_SUCCESS) {
            throw new IOException("SOCKS5: connection error: " + reply[1]);
        }

        if (reply[3] == ADDR_TYPE_IPV4) {
            readExactly(6);
        } else if (reply[3] == ADDR_TYPE_HOSTNAME) {
            byte[] addressLength = readExactly(1);
            readExactly(addressLength[0] + 2);
        } else if (reply[3] == ADDR_TYPE_IPV6) {
            readExactly(18);
        } else {
            throw new IOException("SOCKS5: unknown address type: " + reply[3]);
        }

    }

    /**
     * Returns an {@link InputStream} which can be used to receive data from the connected target.
     * A successful {@link #connect(String, int)} must occur prior to calling this method.
     *
     * @return An {@link InputStream} which can be used to receive data from the connected target.
     *
     * @throws IOException An I/O or SOCKS5 protocol error occurred.
     */
    public InputStream getInputStream() throws IOException {
        return in;
    }

    /**
     * Returns an {@link OutputStream} which can be used to transmit data to the connected target.
     * A successful {@link #connect(String, int)} must occur prior to calling this method.
     *
     * @return An {@link OutputStream} which can be used to transmit data to the connected target.
     *
     * @throws IOException An I/O or SOCKS5 protocol error occurred.
     */
    public OutputStream getOutputStream() throws IOException {
        return out;
    }

    private byte[] readExactly(int count) throws IOException {

        byte[] data = new byte[count];
        int offset = 0;

        while (count > 0) {
            int read = in.read(data, offset, count);
            if (read <= 0) {
                throw new IOException("SOCKS5: unexpected end of stream");
            } else {
                offset += read;
                count -= read;
            }
        }

        return data;

    }

}