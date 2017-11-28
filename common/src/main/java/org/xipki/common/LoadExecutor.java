/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.common;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class LoadExecutor {

    private static final String PROPKEY_LOADTEST = "org.xipki.loadtest";

    private static final int DEFAULT_DURATION = 30; // 30 seconds

    private static final int DEFAULT_THREADS = 25;

    private boolean interrupted;

    private String description;

    private final ProcessLog processLog;

    private int duration = DEFAULT_DURATION; // in seconds

    private int threads = DEFAULT_THREADS;

    private AtomicLong errorAccount = new AtomicLong(0);

    private String unit = "";

    public LoadExecutor(final String description) {
        this.description = ParamUtil.requireNonNull("description", description);
        this.processLog = new ProcessLog(0);
    }

    protected abstract Runnable getTestor() throws Exception;

    protected void shutdown() {
    }

    public void test() {
        System.getProperties().setProperty(PROPKEY_LOADTEST, "true");
        List<Runnable> runnables = new ArrayList<>(threads);
        for (int i = 0; i < threads; i++) {
            Runnable runnable;
            try {
                runnable = getTestor();
            } catch (Exception ex) {
                System.err.println("could not initialize Testor: " + ex.getMessage());
                return;
            }

            runnables.add(runnable);
        }

        StringBuilder sb = new StringBuilder();
        if (StringUtil.isNotBlank(description)) {
            sb.append(description);
            char ch = description.charAt(description.length() - 1);
            if (ch != '\n') {
                sb.append('\n');
            }
        }
        sb.append("threads: ").append(threads).append("\n");
        sb.append("duration: ").append(StringUtil.formatTime(duration, false));
        System.out.println(sb.toString());

        resetStartTime();

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        for (Runnable runnable : runnables) {
            executor.execute(runnable);
        }

        executor.shutdown();
        printHeader();
        while (true) {
            printStatus();
            try {
                boolean terminated = executor.awaitTermination(1, TimeUnit.SECONDS);
                if (terminated) {
                    break;
                }
            } catch (InterruptedException ex) {
                interrupted = true;
            }
        }

        printStatus();
        printSummary();

        shutdown();
        System.getProperties().remove(PROPKEY_LOADTEST);
    } // method test

    public boolean isInterrupted() {
        return interrupted;
    }

    public void setDuration(final String duration) {
        ParamUtil.requireNonBlank("duration", duration);
        char unit = duration.charAt(duration.length() - 1);

        String numStr;
        if (unit == 's' || unit == 'm' || unit == 'h') {
            numStr = duration.substring(0, duration.length() - 1);
        } else {
            unit = 's';
            numStr = duration;
        }

        int num;
        try {
            num = Integer.parseInt(numStr);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("invalid duration " + duration);
        }

        if (num < 1) {
            throw new IllegalArgumentException("invalid duration " + duration);
        }

        switch (unit) {
        case 's':
            this.duration = num;
            break;
        case 'm':
            this.duration = num * 60;
            break;
        case 'h':
            this.duration = num * 60 * 24;
            break;
        default:
            throw new RuntimeException("invalid duration unit " + unit);
        }
    }

    public void setThreads(final int threads) {
        if (threads > 0) {
            this.threads = threads;
        }
    }

    public long getErrorAccout() {
        return errorAccount.get();
    }

    public void account(final int all, final int failed) {
        processLog.addNumProcessed(all);
        errorAccount.addAndGet(failed);
    }

    protected void resetStartTime() {
        processLog.reset();
    }

    protected boolean stop() {
        return interrupted
                || errorAccount.get() > 0
                || System.currentTimeMillis() - processLog.startTimeMs() >= duration * 1000L;
    }

    protected void printHeader() {
        processLog.printHeader();
    }

    protected void printStatus() {
        processLog.printStatus();
    }

    public void setUnit(final String unit) {
        this.unit = ParamUtil.requireNonNull("unit", unit);
    }

    protected void printSummary() {
        processLog.printTrailer();

        final long account = processLog.numProcessed();
        StringBuilder sb = new StringBuilder(400);

        String text = new Date(processLog.startTimeMs()).toString();
        sb.append(" started at: ").append(text).append("\n");

        text = new Date(processLog.endTimeMs()).toString();
        sb.append("finished at: ").append(text).append("\n");

        long elapsedTimeMs = processLog.totalElapsedTime();
        text = StringUtil.formatTime(elapsedTimeMs / 1000, false);
        sb.append("   duration: ").append(text).append("\n");

        text = StringUtil.formatAccount(account, 1);
        sb.append("    account: ").append(text).append(" ").append(unit).append("\n");

        text = StringUtil.formatAccount(errorAccount.get(), 1);
        sb.append("     failed: ").append(text).append(" ").append(unit).append("\n");

        text = StringUtil.formatAccount(processLog.totalAverageSpeed(), 1);
        sb.append("    average: ").append(text).append(" ").append(unit).append("/s\n");

        System.out.println(sb.toString());
    }

    protected static long getSecureIndex() {
        SecureRandom random = new SecureRandom();
        while (true) {
            long nextLong = random.nextLong();
            if (nextLong > 0) {
                return nextLong;
            }
        }
    }

}
