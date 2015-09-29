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

package org.xipki.common;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.xipki.common.qa.MeasurePoint;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 */

public abstract class LoadExecutor
{
    private static final String PROPKEY_LOADTEST = "org.xipki.loadtest";

    private boolean interrupted = false;

    private String description;

    public LoadExecutor(
            final String description)
    {
        ParamUtil.assertNotNull("description", description);
        this.description = description;
    }

    protected abstract Runnable getTestor()
    throws Exception;

    public void test()
    {
        System.getProperties().setProperty(PROPKEY_LOADTEST, "true");
        List<Runnable> runnables = new ArrayList<>(threads);
        for (int i = 0; i < threads; i++)
        {
            Runnable runnable;
            try
            {
                runnable = getTestor();
            } catch (Exception e)
            {
                System.err.println("could not initialize Testor\nError message: " + e.getMessage());
                return;
            }

            runnables.add(runnable);
        }

        StringBuilder sb = new StringBuilder();
        if (StringUtil.isNotBlank(description))
        {
            sb.append(description);
            char c = description.charAt(description.length() - 1);
            if (c != '\n')
            {
                sb.append('\n');
            }
        }
        sb.append("threads: ").append(threads).append("\n");
        sb.append("duration: ").append(StringUtil.formatTime(duration, false));
        System.out.println(sb.toString());

        resetStartTime();

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        for (Runnable runnable : runnables)
        {
            executor.execute(runnable);
        }

        executor.shutdown();
        printHeader();
        while (true)
        {
            printStatus();
            try
            {
                boolean terminated = executor.awaitTermination(1, TimeUnit.SECONDS);
                if (terminated)
                {
                    break;
                }
            } catch (InterruptedException e)
            {
                interrupted = true;
            }
        }

        printStatus();
        printSummary();

        System.getProperties().remove(PROPKEY_LOADTEST);
    }

    private final ConcurrentLinkedDeque<MeasurePoint> measureDeque = new ConcurrentLinkedDeque<>();

    public boolean isInterrupted()
    {
        return interrupted;
    }

    private static int DEFAULT_DURATION = 30; // 30 seconds
    private int duration = DEFAULT_DURATION; // in seconds
    public void setDuration(
            final int duration)
    {
        if (duration > 0)
        {
            this.duration = duration;
        }
    }

    private static int DEFAULT_THREADS = 25;
    private int threads = DEFAULT_THREADS;
    public void setThreads(
            final int threads)
    {
        if (threads > 0)
        {
            this.threads = threads;
        }
    }

    private AtomicLong account = new AtomicLong(0);
    private AtomicLong errorAccount = new AtomicLong(0);

    public long getErrorAccout()
    {
        return errorAccount.get();
    }

    protected void account(
            final int all,
            final int failed)
    {
        account.addAndGet(all);
        errorAccount.addAndGet(failed);
    }

    private long startTime = 0;
    protected void resetStartTime()
    {
        startTime = System.currentTimeMillis();
        measureDeque.add(new MeasurePoint(startTime, 0));
    }

    protected boolean stop()
    {
        return interrupted
                || errorAccount.get() > 0
                || System.currentTimeMillis() - startTime >= duration * 1000L;
    }

    protected static void printHeader()
    {
        System.out.println(
                "------------------------------------------------------------");
        System.out.println(
                "   processed     average     current     elapsed");
        System.out.println(
                "      number       speed       speed        time");
        System.out.println();
        System.out.flush();
    }

    protected void printStatus()
    {
        long currentAccount = account.get();
        long now = System.currentTimeMillis();
        measureDeque.addLast(new MeasurePoint(now, currentAccount));

        MeasurePoint referenceMeasurePoint;
        int numMeasurePoints = measureDeque.size();
        if (numMeasurePoints > 5)
        {
            referenceMeasurePoint = measureDeque.removeFirst();
        } else
        {
            referenceMeasurePoint = measureDeque.getFirst();
        }

        // elapsed time
        long elapsedTimeMs = now - startTime;

        // current speed
        long currentSpeed = 0;
        long t2inms = now - referenceMeasurePoint.getMeasureTime(); // in ms
        if (t2inms > 0)
        {
            currentSpeed = (currentAccount - referenceMeasurePoint.getMeasureAccount())
                    * 1000 / t2inms;
        }

        // average speed
        long averageSpeed = 0;

        if (elapsedTimeMs > 0)
        {
            averageSpeed = currentAccount * 1000 / elapsedTimeMs;
        }

        StringBuilder sb = new StringBuilder("\r");

        // processed number
        sb.append(StringUtil.formatAccount(currentAccount, true));

        // average speed
        sb.append(StringUtil.formatAccount(averageSpeed, true));

        // current speed
        sb.append(StringUtil.formatAccount(currentSpeed, true));

        // elapsed time
        sb.append(StringUtil.formatTime(elapsedTimeMs / 1000, true));

        System.out.print(sb.toString());
        System.out.flush();
    }

    private String unit = "";
    public void setUnit(
            final String unit)
    {
        if (unit != null)
        {
            this.unit = unit;
        }
    }

    protected static long getSecureIndex()
    {
        SecureRandom random = new SecureRandom();
        while (true)
        {
            long l = random.nextLong();
            if (l > 0)
            {
                return l;
            }
        }
    }

    protected void printSummary()
    {
        StringBuilder sb = new StringBuilder();
        long ms = (System.currentTimeMillis() - startTime);
        sb.append("\nfinished in " + StringUtil.formatTime(ms / 1000, false) + "\n");
        sb.append("account: " + account.get() + " " + unit + "\n");
        sb.append(" failed: " + errorAccount.get() + " " + unit + "\n");
        sb.append("average: " + (account.get() * 1000 / ms) + " " + unit + "/s\n");
        System.out.println(sb.toString());
    }

}
