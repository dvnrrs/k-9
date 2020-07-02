package com.fsck.k9.mail.ssl;

import com.fsck.k9.mail.MessagingException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public interface TrustedSocketFactory {
    Socket createSocket(Socket socket, String host, int port, String clientCertificateAlias)
            throws NoSuchAlgorithmException, KeyManagementException, MessagingException, IOException;
    SynchronousSslStreams startTls(InputStream in, OutputStream out, String host, int port, String clientCertificateAlias)
            throws NoSuchAlgorithmException, MessagingException, KeyManagementException;
}