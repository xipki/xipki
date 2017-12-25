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

package org.xipki.common.util;

import java.math.BigInteger;

import javax.xml.bind.JAXBException;

import org.slf4j.Logger;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class LogUtil {

    private LogUtil() {
    }

    public static void error(final Logger log, final Throwable th) {
        if (!log.isErrorEnabled()) {
            return;
        }

        // this operation is expensive, hence don't abuse it.
        StackTraceElement[] traces = Thread.currentThread().getStackTrace();
        if (traces.length > 2) {
            StackTraceElement trace = traces[2];
            log.error("({} {}), {}: {}", trace.getMethodName(), trace.getLineNumber(),
                    th.getClass().getName(), getMessage(th));
        } else {
            log.error("{}: {}", th.getClass().getName(), getMessage(th));
        }
        log.debug("Exception", th);
    }

    public static void error(final Logger log, final Throwable th, final String msg) {
        if (!log.isErrorEnabled()) {
            return;
        }

        // this operation is expensive, hence don't abuse it.
        StackTraceElement[] traces = Thread.currentThread().getStackTrace();
        if (traces.length > 2) {
            StackTraceElement trace = traces[2];
            log.error("({} {}) {}, {}: {}", trace.getMethodName(), trace.getLineNumber(), msg,
                    th.getClass().getName(), getMessage(th));
        } else {
            log.error("{}, {}: {}", msg, th.getClass().getName(), getMessage(th));
        }
        log.debug(msg, th);
    }

    public static void warn(final Logger log, final Throwable th) {
        if (!log.isWarnEnabled()) {
            return;
        }

        // this operation is expensive, don't abuse it.
        StackTraceElement[] traces = Thread.currentThread().getStackTrace();
        if (traces.length > 2) {
            StackTraceElement trace = traces[2];
            log.error("({} {}), {}: {}", trace.getMethodName(), trace.getLineNumber(),
                    th.getClass().getName(), getMessage(th));
        } else {
            log.warn("{}: {}", th.getClass().getName(), getMessage(th));
        }
        log.debug("Exception", th);
    }

    public static void warn(final Logger log, final Throwable th, final String msg) {
        if (!log.isWarnEnabled()) {
            return;
        }

        // this operation is expensive, hence don't abuse it.
        StackTraceElement[] traces = Thread.currentThread().getStackTrace();
        if (traces.length > 2) {
            StackTraceElement trace = traces[2];
            log.warn("({} {}) {}, {}: {}", trace.getMethodName(), trace.getLineNumber(), msg,
                    th.getClass().getName(), getMessage(th));
        } else {
            log.warn("{}, {}: {}", msg, th.getClass().getName(), getMessage(th));
        }
        log.debug(msg, th);
    }

    /**
     * Formats certificate serial number.
     * @param serialNumber certificate serial number
     * @return formatted certificate serial number
     */
    public static String formatCsn(final BigInteger serialNumber) {
        return "0x" + serialNumber.toString(16);
    }

    private static String getMessage(final Throwable th) {
        return (th instanceof JAXBException)
            ? XmlUtil.getMessage((JAXBException) th) : th.getMessage();
    }

}
