/*
 * Java Scan, a library for scanning and configuring HBM devices.
 * Copyright (C) 2014 Stephan Gatzka
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Academic Free License (AFL 3.0)
 * that is bundled with this package in the file LICENSE.
 * It is also available through the world-wide-web at this URL:
 * http://opensource.org/licenses/afl-3.0.php
 */

package com.hbm.devices.scan.messages;

public class ConfigureParams {

    private com.hbm.devices.configure.Device device;
    private com.hbm.devices.configure.NetSettings netSettings;
    private int ttl;

    private ConfigureParams() {
    }

    public ConfigureParams(com.hbm.devices.configure.Device device,
            com.hbm.devices.configure.NetSettings netSettings) {
        this();
        this.device = device;
        this.netSettings = netSettings;
        this.ttl = 1;
    }

    public ConfigureParams(com.hbm.devices.configure.Device device,
            com.hbm.devices.configure.NetSettings netSettings, int ttl) {
        this(device, netSettings);
        this.ttl = ttl;
    }

    public com.hbm.devices.configure.Device getDevice() {
        return device;
    }

    public com.hbm.devices.configure.NetSettings getNetSettings() {
        return netSettings;
    }

    /**
     * @return An optional key which limits the number of router hops a configure request/response
     *         can cross. Leaving out this key should default to a ttl (Time to live) of 1 when
     *         sending datagrams, so no router boundary is crossed.
     */
    public int getTtl() {
        return ttl;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (device != null) {
            sb.append(device);
        }
        if (netSettings != null) {
            sb.append(netSettings);
        }
        sb.append("ttl: " + ttl + "\n");

        sb.append("\n");

        return sb.toString();
    }

    public static void checkForErrors(ConfigureParams params) throws MissingDataException {
        if (params == null) {
            throw new IllegalArgumentException("params object must not be null");
        }

        if (params.ttl < 1) {
            throw new MissingDataException(
                    "time-to-live must be greater or equals 1 in ConfigureParams");
        }

        if (params.device == null) {
            throw new IllegalArgumentException("No device in ConfigureParams");
        }
        com.hbm.devices.configure.Device.checkForErrors(params.device);

        if (params.netSettings == null) {
            throw new IllegalArgumentException("No net settings in ConfigureParams");
        }
        com.hbm.devices.configure.NetSettings.checkForErrors(params.netSettings);
    }
}
