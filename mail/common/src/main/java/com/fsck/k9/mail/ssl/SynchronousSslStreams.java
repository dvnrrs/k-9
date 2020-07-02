package com.fsck.k9.mail.ssl;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

public class SynchronousSslStreams {

    private SSLEngine engine;

    private OutputStream sslDataOut;
    private InputStream sslDataIn;

    private SslInputStream appDataIn;
    private SslOutputStream appDataOut;

    private ByteBuffer SSL_IN = ByteBuffer.allocate(32 * 1024);
    private ByteBuffer SSL_OUT = ByteBuffer.allocate(32 * 1024);
    private ByteBuffer APP_IN = ByteBuffer.allocate(32 * 1024);
    private ByteBuffer APP_OUT = ByteBuffer.allocate(32 * 1024);

    private static final String TAG = "SynchronousSslStreams";

    public SynchronousSslStreams(SSLEngine engine, InputStream in, OutputStream out) {

        this.sslDataIn = in;
        this.sslDataOut = out;
        this.engine = engine;

        this.appDataIn = new SslInputStream();
        this.appDataOut = new SslOutputStream();

        this.SSL_IN.flip();
        this.SSL_OUT.flip();
        this.APP_IN.flip();
        this.APP_OUT.flip();

    }

    public InputStream getInputStream() {
        return appDataIn;
    }

    public OutputStream getOutputStream() {
        return appDataOut;
    }

    private static String toString(ByteBuffer b) {
        if (b == null) {
            return "null";
        } else {
            return b.position() + ":" + b.limit();
        }
    }

    private void close() {
        if (engine != null) {
            engine = null;
            try {
                sslDataIn.close();
            } catch (Exception ex) {}
            try {
                sslDataOut.close();
            } catch (Exception ex) {}
            APP_OUT = SSL_IN = SSL_OUT = null;
        }
    }

    private void expand(int depth, ByteBuffer buffer) {
        ByteBuffer bigger = ByteBuffer.allocate(buffer.capacity() * 2);
        bigger.put(buffer).flip();
        buffer = bigger;
    }

    private void readFromInput(int depth) throws IOException {

        SSL_IN.compact();
        if (!SSL_IN.hasRemaining()) {
            SSL_IN.flip();
            expand(depth + 1, SSL_IN);
            SSL_IN.compact();
        }

        int rv = sslDataIn.read(SSL_IN.array(), SSL_IN.arrayOffset() + SSL_IN.position(), SSL_IN.remaining());

        if (rv < 0) {
            throw new EOFException();
        }

        SSL_IN.position(SSL_IN.position() + rv);
        SSL_IN.flip();

    }

    private void writeToOutput(int depth) throws IOException {
        sslDataOut.write(SSL_OUT.array(), SSL_OUT.arrayOffset() + SSL_OUT.position(), SSL_OUT.remaining());
        sslDataOut.flush();
        SSL_OUT.position(0).limit(0);
    }

    private void task(int depth) {
        Runnable runnable = engine.getDelegatedTask();
        runnable.run();
    }

    private void wrap(int depth) throws IOException {

        while (true) {

            SSL_OUT.compact();
            SSLEngineResult result = engine.wrap(APP_OUT, SSL_OUT);
            SSL_OUT.flip();

            if (SSL_OUT.hasRemaining()) {
                writeToOutput(depth + 1);
            }

            switch (result.getStatus()) {

                case CLOSED:
                    throw new EOFException();

                case BUFFER_OVERFLOW:
                    expand(depth + 1, APP_IN);
                    break;

                case BUFFER_UNDERFLOW:
                    readFromInput(depth + 1);
                    break;

                case OK:

                    switch (result.getHandshakeStatus()) {

                        case NEED_TASK:
                            task(depth + 1);
                            break;

                        case NEED_WRAP:
                            break;

                        case NEED_UNWRAP:
                            unwrap(depth + 1);
                            return;

                        case FINISHED:
                        case NOT_HANDSHAKING:
                            return;

                    }

                    break;

            }

        }

    }

    private void unwrap(int depth) throws IOException {

        while (true) {

            APP_IN.compact();
            SSLEngineResult result = engine.unwrap(SSL_IN, APP_IN);
            APP_IN.flip();

            switch (result.getStatus()) {

                case CLOSED:
                    throw new EOFException();

                case BUFFER_OVERFLOW:
                    expand(depth + 1, APP_IN);
                    break;

                case BUFFER_UNDERFLOW:
                    readFromInput(depth + 1);
                    break;

                case OK:

                    switch (result.getHandshakeStatus()) {

                        case NEED_TASK:
                            task(depth + 1);
                            break;

                        case NEED_WRAP:
                            wrap(depth + 1);
                            return;

                        case NEED_UNWRAP:
                            break;

                        case FINISHED:
                        case NOT_HANDSHAKING:
                            return;

                    }

                    break;

            }

        }

    }

    private class SslInputStream extends InputStream {

        private static final String TAG = "SslInputStream";

        @Override
        public int read() throws IOException {
            byte[] b = new byte[1];
            if (1 == read(b, 0, 1)) {
                return b[0] & 0xff;
            } else {
                return -1;
            }
        }

        @Override
        public int read(byte b[], int off, int len) throws IOException {
            try {
                int rv = innerRead(b, off, len);
                return rv;
            } catch (Exception ex) {
                throw ex;
            }
        }

        @Override
        public void close() throws IOException {
            APP_IN = SSL_IN = null;
            if (APP_OUT == null && SSL_OUT == null) {
                SynchronousSslStreams.this.close();
            }
        }

        private int innerRead(byte b[], int off, int len) throws IOException {
            if (len == 0) {
                return engine == null ? -1 : 0;
            }
            else if (APP_IN == null || SSL_IN == null) {
                return -1;
            }
            try {
                while (!APP_IN.hasRemaining()) {
                    unwrap(1);
                }
                len = Math.min(len, APP_IN.remaining());
                String str = "DATA: ";
                for (int i = 0; i < len; ++i) {
                    int bb =  APP_IN.array()[APP_IN.arrayOffset() + APP_IN.position() + i] & 0xff;
                    str += (bb >= 32 && bb <= 127) ? (char) bb : '.';
                }
                APP_IN.get(b, off, len);
                APP_IN.compact();
                APP_IN.flip();
                return len;
            } catch (IOException ex) {
                close();
                throw ex;
            }
        }

    }

    private class SslOutputStream extends OutputStream {

        private static final String TAG = "SslOutputStream";

        @Override
        public void write(int b) throws IOException {
            byte[] bb = new byte[] { (byte) b };
            write(bb, 0, 1);
        }

        @Override
        public void write(byte b[], int off, int len) throws IOException {
            if (APP_OUT == null || SSL_OUT == null) {
                throw new EOFException();
            }
            try {
                APP_OUT.compact();
                if (APP_OUT.remaining() < len) {
                    APP_OUT.flip();
                    flush();
                    while (APP_OUT.capacity() < len) {
                        expand(1, APP_OUT);
                    }
                    APP_OUT.compact();
                }
                APP_OUT.put(b, off, len);
                APP_OUT.flip();
            } catch (IOException ex) {
                close();
                throw ex;
            }
        }

        @Override
        public void flush() throws IOException {
            if (APP_OUT == null || SSL_OUT == null) {
                return;
            }
            try {
                while (APP_OUT.hasRemaining()) {
                    wrap(1);
                }
            } catch (IOException ex) {
                close();
                throw ex;
            }
        }

        @Override
        public void close() throws IOException {
            APP_OUT = SSL_OUT = null;
            if (APP_IN == null && SSL_IN == null) {
                SynchronousSslStreams.this.close();
            }
        }

    }

}