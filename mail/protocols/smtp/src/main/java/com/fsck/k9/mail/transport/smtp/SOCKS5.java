package com.fsck.k9.mail.transport.smtp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SOCKS5 {

    public static void request(InputStream in, OutputStream out, String host, int port) throws IOException {
        sendGreeting(out);
        waitForGreetingReply(in);
        sendRequest(out, host, port);
        waitForRequestReply(in);
    }

    private static void sendGreeting(OutputStream out) throws IOException {
        byte[] greeting = new byte[3];
        greeting[0] = 5;
        greeting[1] = 1;
        greeting[2] = 0;
        out.write(greeting);
        out.flush();
    }

    private static void sendRequest(OutputStream out, String host, int port) throws IOException {
        int n = host.length();
        byte[] request = new byte[7 + n];
        request[0] = 5;
        request[1] = 1;
        request[2] = 0;
        request[3] = 3;
        request[4] = (byte) n;
        for (int i = 0; i < n; ++i) {
            request[5 + i] = (byte) host.charAt(i);
        }
        request[5 + n] = (byte) (port >> 8);
        request[6 + n] = (byte) port;
        out.write(request);
        out.flush();
    }

    private static void waitForGreetingReply(InputStream in) throws IOException {
        byte[] reply = new byte[2];
        readExactly(in, reply, 0, 2);
        if (reply[0] != 5) {
            throw new IOException("SOCKS5: corrupt handshake reply");
        } else if (reply[1] != 0) {
            throw new IOException("SOCKS5: unsupported authentication method: " + Integer.toString(reply[1]));
        }
    }

    private static void waitForRequestReply(InputStream in) throws IOException {
        byte[] reply = new byte[4];
        readExactly(in, reply, 0, 4);
        if (reply[0] != 5) {
            throw new IOException("SOCKS5: corrupt handshake reply");
        } else if (reply[1] != 0) {
            throw new IOException("SOCKS5: connect error from server: " + Integer.toString(reply[1]));
        }
        byte[] address;
        if (reply[3] == 1) {
            address = new byte[6];
        } else if (reply[3] == 3) {
            readExactly(in, reply, 0, 1);
            address = new byte[reply[0] + 2];
        } else if (reply[3] == 4) {
            address = new byte[18];
        } else {
            throw new IOException("SOCKS5: unknown address type in server reply: " + Integer.toString(reply[3]));
        }
        readExactly(in, address, 0, address.length);
    }

    private static void readExactly(InputStream in, byte[] b, int offset, int count) throws IOException {
        while (count > 0) {
            int r = in.read(b, offset, count);
            if (r <= 0) {
                throw new IOException("SOCKS5: short read");
            } else {
                offset += r;
                count -= r;
            }
        }
    }
}
