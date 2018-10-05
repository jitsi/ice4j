/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.ice.harvest;

import java.io.*;
import java.net.*;
import java.util.*;

import org.ice4j.*;
import org.ice4j.ice.*;
import org.ice4j.socket.*;

/**
 * Implements a <tt>CandidateHarvester</tt> which gathers Google TURN SSLTCP
 * dialect <tt>Candidate</tt>s for a specified {@link Component}.
 *
 * This dialect exchanges a SSL v2.0 client-hello answered by a TLS v1.0
 * server-hello, before TURN data is exchanged. The data is SSL-spec compliant,
 * but use hard-coded values for data that typically aught to be generated
 * (for example: challenge, session-id and random fields).
 *
 * @author Sebastien Vincent
 */
public class GoogleTurnSSLCandidateHarvester
    extends GoogleTurnCandidateHarvester
{
    /**
     * Data for the SSL message sent by the server ('server-hello').
     */
    static final byte SSL_SERVER_HANDSHAKE[] =
    {
        // Content type: Handshake
        0x16,

        // Version: TLS 1.0
        0x03, 0x01,

        // Length: 74
        0x00, 0x4a,

        // Handshake Layer starts here

        // Handshake type: Server Hello
        0x02,

        // Length: 70
        0x00, 0x00, 0x46,

        // Version: TLS 1.0
        0x03, 0x01,

        // 32 bytes random (well, obviously hardcoded here)
        0x42, (byte)0x85, 0x45, (byte)0xa7, 0x27, (byte)0xa9,
        0x5d, (byte)0xa0, (byte)0xb3, (byte)0xc5, (byte)0xe7,
        0x53, (byte)0xda, 0x48, 0x2b, 0x3f, (byte)0xc6, 0x5a,
        (byte)0xca, (byte)0x89, (byte)0xc1, 0x58, 0x52,
        (byte)0xa1, 0x78, 0x3c, 0x5b, 0x17, 0x46, 0x00,
        (byte)0x85, 0x3f,

        // Session-ID length: 32
        0x20,

        // Session-ID
        0x0e, (byte)0xd3, 0x06, 0x72, 0x5b, 0x5b, 0x1b, 0x5f,
        0x15, (byte)0xac, 0x13, (byte)0xf9, (byte)0x88, 0x53,
        (byte)0x9d, (byte)0x9b, (byte)0xe8, 0x3d, 0x7b, 0x0c,
        0x30, 0x32, 0x6e, 0x38, 0x4d, (byte)0xa2, 0x75, 0x57,
        0x41, 0x6c, 0x34, 0x5c,

        // Selected Cipher suite
        0x00, 0x04, // TLS_RSA_WITH_RC4_128_MD5

        // Compression method: null
        0x00
    };

    /**
     * Data for the SSL message sent by the client (client-hello).
     */
    public static final byte SSL_CLIENT_HANDSHAKE[] =
    {
        // Version: SSL 2.0 (0x0002) and length: 70
        (byte)0x80, 0x46,

        // Handshake message type: Client Hello
        0x01,

        // Version TLS 1.0
        0x03, 0x01,

        // Cipher Spec Length: 45
        0x00, 0x2d,

        // Session ID: 0
        0x00, 0x00,

        // Challenge length: 16
        0x00, 0x10,

        // Cipher spec (15 cyphers)
        0x01, 0x00, (byte)0x80,       // SSL2_RC4_128_WITH_MD5
        0x03, 0x00, (byte)0x80,       // SSL2_rc2_128_CBC_WITH_MD5
        0x07, 0x00, (byte)0xc0,       // SSL2_DES_192_EDE3_CBC_WITH_MD5
        0x06, 0x00, 0x40,             // SSL2_DES_64_CBC_WITH_MD5
        0x02, 0x00, (byte)0x80,       // SSL2_RC4_128_EXPORT40_WITH_MD5
        0x04, 0x00, (byte)0x80,       // SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
        0x00, 0x00, 0x04,             // TLS_RSA_WITH_RC4_128_MD5
        0x00, (byte)0xfe, (byte)0xff, // SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
        0x00, 0x00, 0x0a,             // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00, (byte)0xfe, (byte)0xfe, // SSL_RSA_FIPS_WITH_DES_CBC_SHA
        0x00, 0x00, 0x09,             // TLS_RSA_WITH_DES_CBC_SHA
        0x00, 0x00, 0x64,             // TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
        0x00, 0x00, 0x62,             // TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
        0x00, 0x00, 0x03,             // TLS_RSA_EXPORT_WITH_RC4_40_MD5
        0x00, 0x00, 0x06,             // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5

        // Challenge
        0x1f, 0x17, 0x0c, (byte)0xa6, 0x2f, 0x00, 0x78, (byte)0xfc, 0x46,
        0x55, 0x2e, (byte)0xb1, (byte)0x83, 0x39, (byte)0xf1, (byte)0xea
    };

    /**
     * Initializes a new <tt>GoogleTurnSSLCandidateHarvester</tt> instance which
     * is to work with a specific Google TURN server.
     *
     * @param turnServer the <tt>TransportAddress</tt> of the TURN server the
     * new instance is to work with
     */
    public GoogleTurnSSLCandidateHarvester(TransportAddress turnServer)
    {
        this(turnServer, null, null);
    }

    /**
     * Initializes a new <tt>GoogleTurnSSLCandidateHarvester</tt> instance which is
     * to work with a specific TURN server using a specific username for the
     * purposes of the STUN short-term credential mechanism.
     *
     * @param turnServer the <tt>TransportAddress</tt> of the TURN server the
     * new instance is to work with
     * @param shortTermCredentialUsername the username to be used by the new
     * instance for the purposes of the STUN short-term credential mechanism or
     * <tt>null</tt> if the use of the STUN short-term credential mechanism is
     * not determined at the time of the construction of the new instance
     * @param password The gingle candidates password necessary to use this TURN
     * server.
     */
    public GoogleTurnSSLCandidateHarvester(TransportAddress turnServer,
            String shortTermCredentialUsername,
            String password)
    {
        super(turnServer, shortTermCredentialUsername, password);
    }

    /**
     * Creates a new <tt>GoogleTurnSSLCandidateHarvest</tt> instance which is to
     * perform TURN harvesting of a specific <tt>HostCandidate</tt>.
     *
     * @param hostCandidate the <tt>HostCandidate</tt> for which harvesting is
     * to be performed by the new <tt>TurnCandidateHarvest</tt> instance
     * @return a new <tt>GoogleTurnSSLCandidateHarvest</tt> instance which is to
     * perform TURN harvesting of the specified <tt>hostCandidate</tt>
     * @see StunCandidateHarvester#createHarvest(HostCandidate)
     */
    @Override
    protected GoogleTurnCandidateHarvest createHarvest(
            HostCandidate hostCandidate)
    {
        return
            new GoogleTurnCandidateHarvest(this, hostCandidate, getPassword());
    }

    /**
     * Returns the host candidate.
     * For UDP it simply returns the candidate passed as parameter
     *
     * However for TCP, we cannot return the same hostCandidate because in Java
     * a  "server" socket cannot connect to a destination with the same local
     * address/port (i.e. a Java Socket cannot act as both server/client).
     *
     * @param hostCand HostCandidate
     * @return HostCandidate
     */
    @Override
    protected HostCandidate getHostCandidate(HostCandidate hostCand)
    {
        HostCandidate cand = null;
        Socket sock = null;

        try
        {
            sock = new Socket(stunServer.getAddress(), stunServer.getPort());

            OutputStream outputStream = sock.getOutputStream();
            InputStream inputStream = sock.getInputStream();

            if (sslHandshake(inputStream, outputStream))
            {
                Component parentComponent = hostCand.getParentComponent();
                MultiplexingSocket multiplexing = new MultiplexingSocket(sock);

                cand
                    = new HostCandidate(
                            new IceTcpSocketWrapper(multiplexing),
                            parentComponent,
                            Transport.TCP);
                parentComponent
                    .getParentStream()
                        .getParentAgent()
                            .getStunStack()
                                .addSocket(cand.getStunSocket(null));
                ComponentSocket componentSocket
                    = parentComponent.getComponentSocket();
                if (componentSocket != null)
                {
                    componentSocket.add(multiplexing);
                }
            }
        }
        catch (Exception e)
        {
            cand = null;
        }
        finally
        {
            if ((cand == null) && (sock != null))
            {
                try
                {
                    sock.close();
                }
                catch (IOException ioe)
                {
                    /*
                     * We failed to close sock but that should not be much of a
                     * problem because we were not closing it in earlier
                     * revisions.
                     */
                }
            }
        }
        return cand;
    }

    /**
     * Do the SSL handshake (send client certificate and wait for receive server
     * certificate). We explicitly need <tt>InputStream</tt> and
     * <tt>OutputStream</tt> because some <tt>Socket</tt> may redefine
     * getInputStream()/getOutputStream() and we need the original stream.
     *
     * @param inputStream <tt>InputStream</tt> of the socket
     * @param outputStream <tt>OutputStream</tt> of the socket
     * @return true if the SSL handshake is done
     * @throws IOException if something goes wrong
     */
    public static boolean sslHandshake(InputStream inputStream, OutputStream
        outputStream) throws IOException
    {
        byte data[] = new byte[SSL_SERVER_HANDSHAKE.length];

        outputStream.write(SSL_CLIENT_HANDSHAKE);
        inputStream.read(data);

        outputStream = null;
        inputStream = null;

        if(Arrays.equals(data, SSL_SERVER_HANDSHAKE))
        {
            return true;
        }

        return false;
    }
}
