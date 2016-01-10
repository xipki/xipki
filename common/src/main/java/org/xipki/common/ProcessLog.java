/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.common;

import java.util.Calendar;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.xipki.common.qa.MeasurePoint;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 */

public class ProcessLog {

    private static final long MS_900 = 900L;

    private static final long DAY_IN_SEC = 24L * 60 * 60;

    private static final int minLen = 12;

    private final long total;

    private final boolean hasTotal;

    private long startTimeMs;

    private AtomicLong numProcessed;

    private AtomicLong lastPrintTimeMs;

    private final AtomicBoolean finished = new AtomicBoolean(false);

    private long totalElapsedTimeMs;

    private int totalAverageSpeed;

    private final ConcurrentLinkedDeque<MeasurePoint> measureDeque = new ConcurrentLinkedDeque<>();

    public ProcessLog(
            final long total) {
        this.total = total;
        this.hasTotal = total > 0;
        reset();
    }

    public void printHeader() {
        StringBuilder sb = new StringBuilder();

        // first header line
        int n = hasTotal
                ? 7
                : 4;
        for (int i = 0; i < n * minLen; i++) {
            sb.append('-');
        }
        sb.append('\n');

        // second header line
        sb.append(formatText("processed"));
        if (hasTotal) {
            sb.append(formatText("processed"));
        }
        sb.append(formatText("average"));
        sb.append(formatText("current"));
        sb.append(formatText("elapsed"));
        if (hasTotal) {
            sb.append(formatText("remaining"));
            sb.append(formatText("finish"));
        }
        sb.append('\n');

        // third header line
        sb.append(formatText("number"));
        if (hasTotal) {
            sb.append(formatText("percent"));
        }
        sb.append(formatText("speed"));
        sb.append(formatText("speed"));
        sb.append(formatText("time"));
        if (hasTotal) {
            sb.append(formatText("time"));
            sb.append(formatText("at"));
        }
        sb.append('\n');

        System.out.println(sb.toString());
        System.out.flush();
    }

    public void finish() {
        finished.set(true);
        totalElapsedTimeMs = System.currentTimeMillis() - startTimeMs;

        totalAverageSpeed = 0;
        if (totalElapsedTimeMs > 0) {
            totalAverageSpeed = (int) (numProcessed.get() * 1000 / totalElapsedTimeMs);
        }
    }

    public void printTrailer() {
        finish();
        printStatus(true);
        StringBuilder sb = new StringBuilder();
        sb.append('\n');

        int n = hasTotal
                ? 7
                : 4;
        for (int i = 0; i < n * minLen; i++) {
            sb.append('-');
        }

        System.out.println(sb.toString());
        System.out.flush();
    }

    public long getNumProcessed() {
        return numProcessed.get();
    }

    public long getTotal() {
        return total;
    }

    public void reset() {
        startTimeMs = System.currentTimeMillis();
        numProcessed = new AtomicLong(0);
        lastPrintTimeMs = new AtomicLong(0);
        measureDeque.clear();
        measureDeque.add(new MeasurePoint(startTimeMs, 0));
    }

    public long getStartTime() {
        return startTimeMs;
    }

    public long addNumProcessed(
            final long numProcessed) {
        return this.numProcessed.addAndGet(numProcessed);
    }

    public void printStatus() {
        printStatus(false);
    }

    public long getTotalElapsedTime() {
        if (finished.get()) {
            return totalElapsedTimeMs;
        }

        return System.currentTimeMillis() - startTimeMs;
    }

    public int getTotalAverageSpeed() {
        if (finished.get()) {
            return totalAverageSpeed;
        }

        long elapsedTimeMs = System.currentTimeMillis() - startTimeMs;
        int averageSpeed = 0;
        if (elapsedTimeMs > 0) {
            averageSpeed = (int) (numProcessed.get() * 1000 / elapsedTimeMs);
        }
        return averageSpeed;
    }

    private void printStatus(
            final boolean forcePrint) {
        final long lNowMs = System.currentTimeMillis();
        final long lNumProcessed = numProcessed.get();

        if (!forcePrint && lNowMs - lastPrintTimeMs.get() < MS_900) {
            return;
        }

        measureDeque.addLast(new MeasurePoint(lNowMs, numProcessed.get()));
        lastPrintTimeMs.set(lNowMs);
        long elapsedTimeMs = lNowMs - startTimeMs;

        MeasurePoint referenceMeasurePoint;
        int numMeasurePoints = measureDeque.size();
        if (numMeasurePoints > 10) {
            referenceMeasurePoint = measureDeque.removeFirst();
        } else {
            referenceMeasurePoint = measureDeque.getFirst();
        }

        StringBuilder sb = new StringBuilder("\r");

        // processed number
        sb.append(StringUtil.formatAccount(lNumProcessed, true));

        // processed percent
        if (hasTotal) {
            int percent = (int) (lNumProcessed * 100 / total);
            String percentS = Integer.toString(percent) + "%";
            sb.append(formatText(percentS));
        }

        // average speed
        long averageSpeed = 0;
        if (elapsedTimeMs > 0) {
            averageSpeed = lNumProcessed * 1000 / elapsedTimeMs;
        }
        sb.append(StringUtil.formatAccount(averageSpeed, true));

        // current speed
        long currentSpeed = 0;
        long t2inms = lNowMs - referenceMeasurePoint.getMeasureTime(); // in ms
        if (t2inms > 0) {
            currentSpeed =
                    (lNumProcessed - referenceMeasurePoint.getMeasureAccount()) * 1000 / t2inms;
        }
        sb.append(StringUtil.formatAccount(currentSpeed, true));

        // elapsed time
        sb.append(StringUtil.formatTime(elapsedTimeMs / 1000, true));

        // remaining time and finish at
        if (hasTotal) {
            long remaingTimeMs = -1;
            if (currentSpeed > 0) {
                remaingTimeMs = (total - lNumProcessed) * 1000 / currentSpeed;
            }

            long finishAtMs = -1;
            if (remaingTimeMs != -1) {
                finishAtMs = lNowMs + remaingTimeMs;
            }

            if (remaingTimeMs == -1) {
                sb.append(formatText("--"));
            } else {
                sb.append(StringUtil.formatTime(remaingTimeMs / 1000, true));
            }

            if (finishAtMs == -1) {
                sb.append(formatText("--"));
            } else {
                sb.append(buildDateTime(finishAtMs));
            }
        }

        System.out.print(sb.toString());
        System.out.flush();
    }

    private static String formatText(String text) {
        return StringUtil.formatText(text, minLen);
    }

    private static String buildDateTime(long timeMs) {
        Calendar c = Calendar.getInstance();
        c.setTimeInMillis(timeMs);
        int h = c.get(Calendar.HOUR_OF_DAY);
        int m = c.get(Calendar.MINUTE);
        int s = c.get(Calendar.SECOND);

        c.setTimeInMillis(System.currentTimeMillis());
        c.set(Calendar.HOUR, 0);
        c.set(Calendar.MINUTE, 0);
        c.set(Calendar.SECOND, 0);
        long midNightSec = c.getTimeInMillis() / 1000;

        long days = (timeMs / 1000 - midNightSec) / DAY_IN_SEC;
        StringBuilder sb = new StringBuilder();
        if (h < 10) {
            sb.append('0');
        }
        sb.append(h);

        sb.append(":");
        if (m < 10) {
            sb.append('0');
        }
        sb.append(m);

        sb.append(":");
        if (s < 10) {
            sb.append('0');
        }
        sb.append(s);

        if (days > 0) {
            sb.append('+').append(days);
        }

        int size = sb.length();
        for (int i = 0; i < (minLen - size); i++) {
            sb.insert(0, ' ');
        }

        return sb.toString();
    }
}
