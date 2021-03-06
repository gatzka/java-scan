package com.hbm.devices.scan.announce;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.Observer;
import java.util.Observable;

import com.hbm.devices.scan.FakeMessageReceiver;
import com.hbm.devices.scan.ScanInterfaces;

public class ConnectionFinderTest {

    private Announce announce;
    private FakeMessageReceiver fsmmr;
    
    @BeforeEach
    public void setUp() {
        announce = null;
        fsmmr = new FakeMessageReceiver();
        AnnounceDeserializer parser = new AnnounceDeserializer();
        fsmmr.addObserver(parser);
        parser.addObserver(new Observer() {
            public void update(Observable o, Object arg) {
                if (arg instanceof Announce) {
                    announce = (Announce) arg;
                } 
            }
        });
    }

    @Test
    public void listSizeTest() {
        try {
            ScanInterfaces interfaces = new ScanInterfaces();
            ConnectionFinder finder = new ConnectionFinder(interfaces.getInterfaces());
            assertNotNull(finder, "ConnectionFinder cannot be constructed");
        } catch (SocketException e) {
            fail("Got SocketException while building list of scan interfaces");
        }
    }

    @Test
    public void testConnectableAddress() {
        LinkedList<NetworkInterfaceAddress> ipv4List = new LinkedList<NetworkInterfaceAddress>();
        LinkedList<NetworkInterfaceAddress> ipv6List = new LinkedList<NetworkInterfaceAddress>();
        try {
            ipv4List.push(new NetworkInterfaceAddress(InetAddress.getByName("10.1.2.3"), 8));
            ipv4List.push(new NetworkInterfaceAddress(InetAddress.getByName("172.19.1.2"), 16));
            ipv4List.push(new NetworkInterfaceAddress(InetAddress.getByName("192.168.4.5"), 24));

            ipv6List.push(new NetworkInterfaceAddress(InetAddress.getByName("fe80::222:4dff:feaa:4c1e"), 64));
            ipv6List.push(new NetworkInterfaceAddress(InetAddress.getByName("fdfb:84a3:9d2d:0:d890:1567:3af6:974e"), 64));
            ipv6List.push(new NetworkInterfaceAddress(InetAddress.getByName("2a01:238:20a:202:6660:0000:0198:0033"), 48));
            ConnectionFinder finder = new ConnectionFinder(ipv4List, ipv6List);

            fsmmr.emitSingleCorrectMessage();
            assertNotNull(announce, "No Announce object after correct message");

            assertFalse(finder.getSameNetworkAddresses(announce).isEmpty(), "List of connectable addresses is empty");
        } catch (UnknownHostException e) {
            fail("name resolution failed");
        }
    }
}
