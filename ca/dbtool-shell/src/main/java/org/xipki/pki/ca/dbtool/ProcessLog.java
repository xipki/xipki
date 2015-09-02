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

import java.util.concurrent.ConcurrentLinkedDeque;

import org.xipki.common.qa.AbstractLoadTest;
import org.xipki.common.qa.MeasurePoint;

/**
 * @author Lijun Liao
 */

public class ProcessLog
{
    private static final long MS_800 = 800L;

    private final long total;
    private final long startTime;
    private final long sumInLastProcess;
    private long numProcessed;
    private long lastPrintTime = 0;

    private final ConcurrentLinkedDeque<MeasurePoint> measureDeque = new ConcurrentLinkedDeque<>();

    public static void printHeader()
    {
        System.out.println("----------------------------------------------------------------------------");
        System.out.println("    processed   percent       time       #/s        ETA   AVG-#/s    AVG-ETA");
        System.out.flush();
    }

    public static void printTrailer()
    {
        System.out.println("\n----------------------------------------------------------------------------");
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

    public void printStatus(boolean forcePrint)
    {
        final long now = System.currentTimeMillis();
        if(forcePrint == false && now - lastPrintTime < MS_800)
        {
            return;
        }

        measureDeque.addLast(new MeasurePoint(now, numProcessed));
        lastPrintTime = now;

        StringBuilder sb = new StringBuilder("\r");
        sb.append(AbstractLoadTest.formatAccount(numProcessed));

        // 10 characters for processed percent
        String percent = total > 0 ? Long.toString(numProcessed * 100 / total) : "--";
        for (int i = 0; i < 9 - percent.length(); i++)
        {
            sb.append(" ");
        }
        sb.append(percent).append('%');

        long t = (now - startTime)/1000;  // in s
        String time = AbstractLoadTest.formatTime(t);
        sb.append("  ");
        sb.append(time);

        MeasurePoint referenceMeasurePoint;
        int numMeasurePoints = measureDeque.size();
        if(numMeasurePoints > 10)
        {
            referenceMeasurePoint = measureDeque.removeFirst();
        }
        else
        {
            referenceMeasurePoint = measureDeque.getFirst();
        }

        long speed = 0;
        long t2inms = now - referenceMeasurePoint.getMeasureTime(); // in ms
        if(t2inms > 0)
        {
            speed = (numProcessed - referenceMeasurePoint.getMeasureAccount()) * 1000 / t2inms;
        }
        sb.append(AbstractLoadTest.formatSpeed(speed));

        if(speed > 0)
        {
            long remaining = (total - numProcessed) / speed;
            sb.append("  ");
            sb.append(AbstractLoadTest.formatTime(remaining));
        } else
        {
            sb.append("         --");
        }

        // average

        speed = 0;
        long t2 = now - startTime;
        if(t2 > 0)
        {
            speed = numProcessed * 1000 / t2;
        }
        sb.append(AbstractLoadTest.formatSpeed(speed));

        if(speed > 0)
        {
            long remaining = (total - numProcessed) / speed;
            sb.append("  ");
            sb.append(AbstractLoadTest.formatTime(remaining));
        } else
        {
            sb.append("         --");
        }

        System.out.print(sb.toString());
        System.out.flush();
    }

}
