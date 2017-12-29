/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.dbtool.port;

import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class DbPortWorker implements Runnable {

    private static final Logger LOG = LoggerFactory.getLogger(DbPorter.class);

    protected final AtomicBoolean stopMe = new AtomicBoolean(false);

    private Exception exception;

    public DbPortWorker() {
    }

    public final Exception exception() {
        return exception;
    }

    public void setStopMe(boolean stopMe) {
        this.stopMe.set(stopMe);
    }

    @Override
    public void run() {
        try {
            run0();
        } catch (Exception ex) {
            LOG.error("exception thrown", ex);
            exception = ex;
        }
    }

    protected abstract void run0() throws Exception;

}
