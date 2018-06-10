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

package org.xipki.common;

import java.util.Calendar;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.xipki.common.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ProcessLog {

  private static class MeasurePoint {

    private final long measureTime;

    private final long measureAccount;

    public MeasurePoint(long measureTime, long measureAccount) {
      this.measureTime = measureTime;
      this.measureAccount = measureAccount;
    }

  }

  private static final long MS_900 = 900L;

  private static final long DAY_IN_SEC = 24L * 60 * 60;

  private static final int MIN_LEN = 12;

  private final long total;

  private final boolean hasTotal;

  private long startTimeMs;

  private long endTimeMs;

  private AtomicLong numProcessed;

  private AtomicLong lastPrintTimeMs;

  private final AtomicBoolean finished = new AtomicBoolean(false);

  private long totalElapsedTimeMs;

  private int totalAverageSpeed;

  private final ConcurrentLinkedDeque<MeasurePoint> measureDeque = new ConcurrentLinkedDeque<>();

  public ProcessLog(long total) {
    this.total = total;
    this.hasTotal = total > 0;
    reset();
  }

  public void printHeader() {
    StringBuilder sb = new StringBuilder();

    // first header line
    final int n = hasTotal ? 7 : 4;
    for (int i = 0; i < n * MIN_LEN; i++) {
      sb.append('-');
    }
    sb.append('\n');

    // second header line
    sb.append(formatText("total"));
    if (hasTotal) {
      sb.append(formatText("%"));
    }
    sb.append(formatText("average")).append(formatText("current")).append(formatText("time"));
    if (hasTotal) {
      sb.append(formatText("time")).append(formatText("finish"));
    }
    sb.append('\n');

    // third header line
    sb.append(formatText(""));
    if (hasTotal) {
      sb.append(formatText(""));
    }
    sb.append(formatText("speed")).append(formatText("speed")).append(formatText("spent"));
    if (hasTotal) {
      sb.append(formatText("left")).append(formatText("at"));
    }
    sb.append('\n');

    System.out.println(sb.toString());
    System.out.flush();
  } // method printHeader

  public void finish() {
    finished.set(true);
    endTimeMs = System.currentTimeMillis();
    totalElapsedTimeMs = endTimeMs - startTimeMs;

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

    final int n = hasTotal ? 7 : 4;
    for (int i = 0; i < n * MIN_LEN; i++) {
      sb.append('-');
    }

    System.out.println(sb.toString());
    System.out.flush();
  }

  public long numProcessed() {
    return numProcessed.get();
  }

  public long total() {
    return total;
  }

  public void reset() {
    startTimeMs = System.currentTimeMillis();
    numProcessed = new AtomicLong(0);
    lastPrintTimeMs = new AtomicLong(0);
    measureDeque.clear();
    measureDeque.add(new MeasurePoint(startTimeMs, 0));
  }

  public long startTimeMs() {
    return startTimeMs;
  }

  public long endTimeMs() {
    return endTimeMs;
  }

  public long addNumProcessed(long numProcessed) {
    return this.numProcessed.addAndGet(numProcessed);
  }

  public void printStatus() {
    printStatus(false);
  }

  private void printStatus(boolean forcePrint) {
    final long nowMs = System.currentTimeMillis();
    final long tmpNumProcessed = numProcessed.get();

    if (!forcePrint && nowMs - lastPrintTimeMs.get() < MS_900) {
      return;
    }

    measureDeque.addLast(new MeasurePoint(nowMs, numProcessed.get()));
    lastPrintTimeMs.set(nowMs);

    int numMeasurePoints = measureDeque.size();
    // CHECKSTYLE:SKIP
    MeasurePoint referenceMeasurePoint = (numMeasurePoints > 10) ? measureDeque.removeFirst()
        : measureDeque.getFirst();

    StringBuilder sb = new StringBuilder("\r");

    // processed number
    sb.append(StringUtil.formatAccount(tmpNumProcessed, true));

    // processed percent
    if (hasTotal) {
      int percent = (int) (tmpNumProcessed * 100 / total);
      String percentS = Integer.toString(percent);
      sb.append(formatText(percentS));
    }

    // average speed
    long averageSpeed = 0;
    long elapsedTimeMs = nowMs - startTimeMs;
    if (elapsedTimeMs > 0) {
      averageSpeed = tmpNumProcessed * 1000 / elapsedTimeMs;
    }
    sb.append(StringUtil.formatAccount(averageSpeed, true));

    // current speed
    long currentSpeed = 0;
    long t2inms = nowMs - referenceMeasurePoint.measureTime; // in ms
    if (t2inms > 0) {
      currentSpeed = (tmpNumProcessed - referenceMeasurePoint.measureAccount) * 1000 / t2inms;
    }
    sb.append(StringUtil.formatAccount(currentSpeed, true));

    // elapsed time
    sb.append(StringUtil.formatTime(elapsedTimeMs / 1000, true));

    // remaining time and finish at
    if (hasTotal) {
      long remaingTimeMs = -1;
      if (currentSpeed > 0) {
        remaingTimeMs = (total - tmpNumProcessed) * 1000 / currentSpeed;
      }

      long finishAtMs = -1;
      if (remaingTimeMs != -1) {
        finishAtMs = nowMs + remaingTimeMs;
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
  } // method printStatus

  public long totalElapsedTime() {
    if (finished.get()) {
      return totalElapsedTimeMs;
    }

    return System.currentTimeMillis() - startTimeMs;
  }

  public int totalAverageSpeed() {
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

  private static String formatText(String text) {
    return StringUtil.formatText(text, MIN_LEN);
  }

  private static String buildDateTime(long timeMs) {
    Calendar cal = Calendar.getInstance();
    cal.setTimeInMillis(timeMs);

    StringBuilder sb = new StringBuilder();
    int hour = cal.get(Calendar.HOUR_OF_DAY);
    if (hour < 10) {
      sb.append('0');
    }
    sb.append(hour);

    int minute = cal.get(Calendar.MINUTE);
    sb.append(":");
    if (minute < 10) {
      sb.append('0');
    }
    sb.append(minute);

    int second = cal.get(Calendar.SECOND);
    sb.append(":");
    if (second < 10) {
      sb.append('0');
    }
    sb.append(second);

    cal.setTimeInMillis(System.currentTimeMillis());
    cal.set(Calendar.HOUR, 0);
    cal.set(Calendar.MINUTE, 0);
    cal.set(Calendar.SECOND, 0);
    long midNightSec = cal.getTimeInMillis() / 1000;
    long days = (timeMs / 1000 - midNightSec) / DAY_IN_SEC;
    if (days > 0) {
      sb.append('+').append(days);
    }

    int size = sb.length();
    for (int i = 0; i < (MIN_LEN - size); i++) {
      sb.insert(0, ' ');
    }

    return sb.toString();
  } // method buildDateTime
}
