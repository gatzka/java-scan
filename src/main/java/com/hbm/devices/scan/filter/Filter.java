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

package com.hbm.devices.scan.filter;

import java.util.Observable;
import java.util.Observer;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.hbm.devices.scan.ScanConstants;
import com.hbm.devices.scan.messages.Announce;
import com.hbm.devices.scan.messages.CommunicationPath;
import com.hbm.devices.scan.messages.MissingDataException;

/**
 * This class filters {@link CommunicationPath} objects with according to a {@link Matcher} object.
 * <p>
 * The class reads {@link CommunicationPath} objects and notifies them if
 * {@link Matcher#match(Announce)} method returns true.
 * 
 * @since 1.0
 */
public class Filter extends Observable implements Observer {

    private Matcher matcher;
    private static final Logger LOGGER = Logger.getLogger(ScanConstants.LOGGER_NAME);

    public Filter(Matcher m) {
        this.matcher = m;
    }

    public Matcher getMatcher() {
        return this.matcher;
    }

    @Override
    public void update(Observable o, Object arg) {
        CommunicationPath ap = (CommunicationPath) arg;
        Announce announce = ap.getAnnounce();
        try {
            if (matcher.match(announce)) {
                setChanged();
                notifyObservers(ap);
            }
        } catch (MissingDataException e) {
            LOGGER.log(Level.INFO, "Some information is missing in announce!", e);
        }
    }
}
