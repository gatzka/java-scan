/*
 * Java Scan, a library for scanning and configuring HBM devices.
 *
 * The MIT License (MIT)
 *
 * Copyright (C) Hottinger Baldwin Messtechnik GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.hbm.devices.scan;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

/**
 * This class receives messages from a multicast UDP socket and converts them to a
 * {@link java.lang.String}.
 * <p>
 * All network interfaces that are eligible to receive IPv4 multicast messages (see
 * {@link com.hbm.devices.scan.ScanInterfaces}) are joined.
 * <p>
 * Receiving messages is done infinitely when calling {@link #run() run()}. After calling
 * {@link #close() close()}, {@link #run() run()} returns.
 * <p>
 * In addition, via {@link com.hbm.devices.scan.AbstractMessageReceiver} this class is also an
 * {@link java.util.Observable}. So objects which are interested in String multicast messages have
 * to implement the {@link java.util.Observer} interface and register themselves to an instance of
 * this class with addObserver().
 *
 * @since 1.0
 */
public class MulticastMessageReceiver extends AbstractMessageReceiver {

    private final InetAddress multicastIP;
    private final int port;
    private final Predicate<NetworkInterface> ifacePredicate;
    private boolean shallRun = true;
    private final MulticastSocket socket;
    private static final Logger LOGGER = Logger.getLogger(ScanConstants.LOGGER_NAME);
    private static final int MAX_UDP_SIZE = 65507;

    /**
     * Creates a {@link MulticastMessageReceiver} for receiving
     * multicast messsages
     *
     * @param multicastIP The multicast IP the {@link MulticastMessageReceiver} will listen to.
     * @param port The port for listening to multicast packets.
     *
     * @throws IOException if creating the underlying socket fails.
     */
    public MulticastMessageReceiver(String multicastIP, int port) throws IOException {
        this(InetAddress.getByName(multicastIP), port);
    }

    /**
     * Creates a {@link MulticastMessageReceiver} for receiving
     * multicast messsages
     *
     * @param multicastIP The multicast IP the {@link MulticastMessageReceiver} will listen to.
     * @param port The port for listening to multicast packets.
     * @param ifacePredicate custom filter to be applied to all network interfaces before checking multicast capability.
     *
     * @throws IOException if creating the underlying socket fails.
     */
    public MulticastMessageReceiver(String multicastIP, int port, Predicate<NetworkInterface> ifacePredicate) throws IOException {
        this(InetAddress.getByName(multicastIP), port, ifacePredicate);
    }

    /**
     * Creates a {@link MulticastMessageReceiver} for receiving
     * multicast messsages
     *
     * @param multicastIP The multicast IP the {@link MulticastMessageReceiver} will listen to.
     * @param port The port for listening to multicast packets.
     *
     * @throws IOException if creating the underlying socket fails.
     */
    public MulticastMessageReceiver(InetAddress multicastIP, int port) throws IOException {
        this(multicastIP, port, Predicates.<NetworkInterface>alwaysTrue());
    }

    /**
     * Creates a {@link MulticastMessageReceiver} for receiving
     * multicast messsages
     *
     * @param multicastIP The multicast IP the {@link MulticastMessageReceiver} will listen to.
     * @param port The port for listening to multicast packets.
     * @param ifacePredicate custom filter to be applied to each available network interface
     *        before checking its multicast capability.
     *
     * @throws IOException if creating the underlying socket fails.
     */
    public MulticastMessageReceiver(InetAddress multicastIP, int port, Predicate<NetworkInterface> ifacePredicate) throws IOException {
        super();
        this.multicastIP = multicastIP;
        this.port = port;
        this.ifacePredicate = ifacePredicate;
        this.socket = setupMulticastSocket();
    }

    /**
     * This method starts the listening socket.
     *
     * In an infinite loop this method waits for incoming
     * messages, converts them into strings and forwards them to all observers.
     */
    @Override
    public void run() {
        final byte[] buffer = new byte[MAX_UDP_SIZE];
        final Charset charset = Charset.forName("UTF-8");
        final DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        while (shallRun) {
            try {
                socket.receive(packet);
                final String message = new String(buffer, 0, packet.getLength(), charset);
                setChanged();
                notifyObservers(message);
            } catch (IOException e) {
                /*
                 * No error handling by intention. Receiving announce datagrams is a best effort
                 * service. so don't bother users of the class with error handling.
                 *
                 * Just try receiving the next datagram.
                 *
                 * If shallRun is false - socket has already been closed by close() method.
                 */
                if (shallRun) {
                    LOGGER.log(Level.INFO, "Error receiving Multicast messages!", e);
                }
            }
        }
    }

    /**
     * This method closes the listening socket and cancels the infinite receiving loop.
     */
    @Override
    public void close() {
        shallRun = false;
        try {
            leaveOnAllInterfaces(socket);
            socket.close();
        } catch (IOException e) {
            /*
             * No error handling by intention. Stopping to receive datagrams is best effort.
             */
            LOGGER.log(Level.INFO, "Can't close multicast socket!", e);
        }
    }

    private MulticastSocket setupMulticastSocket() throws IOException {
        final MulticastSocket sock = new MulticastSocket(port);
        sock.setReuseAddress(true);

        joinOnAllInterfaces(sock);
        return sock;
    }

    private void joinOnAllInterfaces(MulticastSocket socket) throws IOException {
        final InetSocketAddress socketAddress = new InetSocketAddress(multicastIP, port);
        final Collection<NetworkInterface> interfaces = new ScanInterfaces(ifacePredicate).getInterfaces();
        for (final NetworkInterface ni : interfaces) {
            socket.joinGroup(socketAddress, ni);
        }
    }

    private void leaveOnAllInterfaces(MulticastSocket socket) throws IOException {
        final Collection<NetworkInterface> interfaces = new ScanInterfaces(ifacePredicate).getInterfaces();
        final InetSocketAddress socketAddress = new InetSocketAddress(multicastIP, port);
        for (final NetworkInterface ni : interfaces) {
            socket.leaveGroup(socketAddress, ni);
        }
    }
}
