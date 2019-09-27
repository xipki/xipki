/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.util;

import java.util.Calendar;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Process Logger.
 *
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

  private static final int DURATION_LEN = 10;

  private static final int PERCENT_LEN = 6;

  private static final int SPEED_LEN = 10;

  private static final int TIME_LEN = 10;

  private static final int TOTAL_LEN = 15;

  private long total;

  private boolean hasTotal;

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
    reset();
  }

  public void printHeader() {
    StringBuilder sb = new StringBuilder();

    final int lineLength = getLineLength();

    // first header line
    for (int i = 0; i < lineLength; i++) {
      sb.append('-');
    }
    sb.append('\n');

    // second header line
    sb.append(formatText("", TOTAL_LEN));
    if (hasTotal) {
      sb.append(formatText("", PERCENT_LEN));
    }
    sb.append(formatText("average", SPEED_LEN))
        .append(formatText("current", SPEED_LEN))
        .append(formatText("time", DURATION_LEN));
    if (hasTotal) {
      sb.append(formatText("time", DURATION_LEN))
        .append(formatText("finish", TIME_LEN));
    }
    sb.append('\n');

    // third header line
    sb.append(StringUtil.formatText("total", TOTAL_LEN));
    if (hasTotal) {
      sb.append(formatText("%", PERCENT_LEN));
    }
    sb.append(formatText("speed", SPEED_LEN))
      .append(formatText("speed", SPEED_LEN))
      .append(formatText("spent", DURATION_LEN));
    if (hasTotal) {
      sb.append(formatText("left", DURATION_LEN))
        .append(formatText("at", TIME_LEN));
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

    final int lineLength = getLineLength();
    for (int i = 0; i < lineLength; i++) {
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

  public void total(long total) {
    this.total = total;
  }

  public final void reset() {
    startTimeMs = System.currentTimeMillis();
    numProcessed = new AtomicLong(0);
    lastPrintTimeMs = new AtomicLong(0);
    measureDeque.clear();
    measureDeque.add(new MeasurePoint(startTimeMs, 0));

    hasTotal = total > 0;
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
    sb.append(StringUtil.formatAccount(tmpNumProcessed, TOTAL_LEN));

    // processed percent
    if (hasTotal) {
      int percent = (int) (tmpNumProcessed * 100 / total);
      String percentS = Integer.toString(percent) + "%";
      sb.append(formatText(percentS, PERCENT_LEN));
    }

    // average speed
    long averageSpeed = 0;
    long elapsedTimeMs = nowMs - startTimeMs;
    if (elapsedTimeMs > 0) {
      averageSpeed = tmpNumProcessed * 1000 / elapsedTimeMs;
    }
    sb.append(StringUtil.formatAccount(averageSpeed, SPEED_LEN));

    // current speed
    long currentSpeed = 0;
    long t2inms = nowMs - referenceMeasurePoint.measureTime; // in ms
    if (t2inms > 0) {
      currentSpeed = (tmpNumProcessed - referenceMeasurePoint.measureAccount) * 1000 / t2inms;
    }
    sb.append(StringUtil.formatAccount(currentSpeed, SPEED_LEN));

    // elapsed time
    sb.append(StringUtil.formatTime(elapsedTimeMs / 1000, DURATION_LEN));

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

      if (remaingTimeMs < 1) {
        sb.append(formatText("--", DURATION_LEN));
      } else {
        sb.append(StringUtil.formatTime(remaingTimeMs / 1000, DURATION_LEN));
      }

      if (remaingTimeMs < 1) {
        sb.append(formatText("--", TIME_LEN));
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

  private static String formatText(String text, int minLen) {
    return StringUtil.formatText(text, minLen);
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
    for (int i = 0; i < (TIME_LEN - size); i++) {
      sb.insert(0, ' ');
    }

    return sb.toString();
  } // method buildDateTime

  private int getLineLength() {
    int len = TOTAL_LEN;
    if (hasTotal) {
      len += PERCENT_LEN;
    }

    len += SPEED_LEN;
    len += SPEED_LEN;
    len += DURATION_LEN;

    if (hasTotal) {
      len += DURATION_LEN;
      len += TIME_LEN;
    }

    return len;
  }
}
