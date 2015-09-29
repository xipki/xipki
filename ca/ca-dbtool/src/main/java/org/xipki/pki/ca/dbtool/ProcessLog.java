/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.pki.ca.dbtool;

import java.util.Calendar;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.xipki.common.qa.MeasurePoint;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 */

public class ProcessLog
{
    private static final long MS_900 = 900L;
    private static final long DAY_IN_SEC = 24L * 60 * 60;

    private final long total;
    private final long startTime;
    private final long sumInLastProcess;
    private long numProcessed;
    private long lastPrintTime = 0;

    private final ConcurrentLinkedDeque<MeasurePoint> measureDeque = new ConcurrentLinkedDeque<>();

    public static void printHeader()
    {
        System.out.println(
        "------------------------------------------------------------------------------------");

        System.out.println(
        "   processed   processed     average     current     elapsed   remaining      finish");

        System.out.println(
        "      number     percent       speed       speed        time        time          at");

        System.out.println();
        System.out.flush();
    }

    public static void printTrailer()
    {
        System.out.println(
        "\n------------------------------------------------------------------------------------");

        System.out.flush();
    }

    public ProcessLog(
            final long total,
            final long startTime,
            final long sumInLastProcess)
    {
        this.total = total;
        this.startTime = startTime;
        this.sumInLastProcess = sumInLastProcess;
        this.numProcessed = 0;
    }

    public long getSumInLastProcess()
    {
        return sumInLastProcess;
    }

    public long getNumProcessed()
    {
        return numProcessed;
    }

    public long getTotal()
    {
        return total;
    }

    public long getStartTime()
    {
        return startTime;
    }

    public long addNumProcessed(
            final long numProcessed)
    {
        this.numProcessed += numProcessed;
        return this.numProcessed;
    }

    public void printStatus()
    {
        printStatus(false);
    }

    public void printStatus(
            final boolean forcePrint)
    {
        final long now = System.currentTimeMillis();
        if (!forcePrint && now - lastPrintTime < MS_900)
        {
            return;
        }

        measureDeque.addLast(new MeasurePoint(now, numProcessed));
        lastPrintTime = now;

        MeasurePoint referenceMeasurePoint;
        int numMeasurePoints = measureDeque.size();
        if (numMeasurePoints > 10)
        {
            referenceMeasurePoint = measureDeque.removeFirst();
        } else
        {
            referenceMeasurePoint = measureDeque.getFirst();
        }

        // percent
        long percent = numProcessed * 100 / total;

        // elapsed time in ms
        long elapsedTimeMs = now - startTime;

        // current speed
        long currentSpeed = 0;
        long t2inms = now - referenceMeasurePoint.getMeasureTime(); // in ms
        if (t2inms > 0)
        {
            currentSpeed =
                    (numProcessed - referenceMeasurePoint.getMeasureAccount()) * 1000 / t2inms;
        }

        // average speed
        long averageSpeed = 0;
        if (elapsedTimeMs > 0)
        {
            averageSpeed = numProcessed * 1000 / elapsedTimeMs;
        }

        // remaining time
        long remaingTimeMs = 0;
        if (currentSpeed > 0)
        {
            remaingTimeMs = (total - numProcessed) * 1000 / currentSpeed;
        }

        // finish at
        long finishAtMs = System.currentTimeMillis() + remaingTimeMs;

        StringBuilder sb = new StringBuilder("\r");

        // processed number
        sb.append(StringUtil.formatAccount(numProcessed, true));

        // processed percent
        String percentS = Long.toString(percent);
        for (int i = 0; i < 11 - percentS.length(); i++)
        {
            sb.append(" ");
        }
        sb.append(percent).append('%');

        // average speed
        sb.append(StringUtil.formatAccount(averageSpeed, true));

        // current speed
        sb.append(StringUtil.formatAccount(currentSpeed, true));

        // elapsed time
        sb.append(StringUtil.formatTime(elapsedTimeMs / 1000, true));

        // remaining time
        sb.append(StringUtil.formatTime(remaingTimeMs / 1000, true));

        // finish at
        sb.append(buildDateTime(finishAtMs));

        System.out.print(sb.toString());
        System.out.flush();
    }

    private static String buildDateTime(long timeMs)
    {
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
        if (h < 10)
        {
            sb.append('0');
        }
        sb.append(h);

        sb.append(":");
        if (m < 10)
        {
            sb.append('0');
        }
        sb.append(m);

        sb.append(":");
        if (s < 10)
        {
            sb.append('0');
        }
        sb.append(s);

        if (days > 0)
        {
            sb.append("+").append(days);
        }

        int size = sb.length();
        for (int i = 0; i < (12 - size); i++)
        {
            sb.insert(0, ' ');
        }

        return sb.toString();
    }

}
