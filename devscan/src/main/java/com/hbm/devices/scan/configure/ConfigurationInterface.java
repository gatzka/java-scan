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

package com.hbm.devices.scan.configure;

import java.io.Serializable;

/**
 * The interface describes the properties and settings of an network interface which are configured.
 * 
 * @since 1.0
 *
 */
public final class ConfigurationInterface implements Serializable {

    private static final long serialVersionUID = -9128366354731289950L;
    private String name;
    private IPv4EntryManual ipv4;
    private String configurationMethod;

    /**
     * This constructor is used to instantiate an {@link ConfigurationInterface} object.
     * <p>
     * Note: The parameter {@code configMethod} must not be {@link Method#MANUAL}. If you want to
     * set a manual ipv4 use the constructor
     * {@link #ConfigurationInterface(String, ConfigurationInterface.Method, IPv4EntryManual)}.
     * <p>
     * 
     * @param interfaceName
     *            this parameter specifies the interface
     * @param configMethod
     *            this parameter specifies the ip configuration method.
     * 
     */
    public ConfigurationInterface(String interfaceName, Method configMethod) {
        this(interfaceName, configMethod, null);
    }

    /**
     * This constructor is used to instantiate an {@link ConfigurationInterface} object.
     * 
     * @param interfaceName
     *            this parameter specifies the interface
     * @param configurationMethod
     *            this parameter specifies the ip configuration method.
     * @param ipv4
     *            this parameter specifies the ip address which is set to this interface
     * @throws IllegalArgumentException if no interface name given of no
     * configuration method given or if the configuration method is
     * {@code manual} but no IP address given.
     */
    public ConfigurationInterface(String interfaceName, Method configurationMethod, IPv4EntryManual ipv4) {
        if ((interfaceName == null) || (interfaceName.length() == 0)) {
            throw new IllegalArgumentException("No interface name given!");
        }
        if (configurationMethod == null) {
            throw new IllegalArgumentException("No configuration method given!");
        }
        if ((configurationMethod == Method.MANUAL) && (ipv4 == null)) {
            throw new IllegalArgumentException("Manual interface configuration but no IP given!");
        }
        this.name = interfaceName;
        this.configurationMethod = configurationMethod.toString();
        this.ipv4 = ipv4;
    }

    /**
     * 
     * @return returns the name of the network interface
     */
    public String getName() {
        return name;
    }

    public String getConfigurationMethod() {
        return configurationMethod;
    }

    /**
     * 
     * @return returns the {@link IPv4EntryManual}
     */
    public IPv4EntryManual getIPv4() {
        return ipv4;
    }

    /**
     * Network interface configuration methods that can be used.
     */
    public enum Method {
        MANUAL {
            @Override
            public String toString() {
                return "manual";
            }
        },
        DHCP {
            @Override
            public String toString() {
                return "dhcp";
            }
        };
    }
}
