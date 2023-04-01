// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Process Logger.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class ProcessLog {

  private static class MeasurePoint {

    private final Instant measureTime;

    private final long measureAccount;

    public MeasurePoint(Instant measureTime, long measureAccount) {
      this.measureTime = measureTime;
      this.measureAccount = measureAccount;
    }

  }

  private static final long MS_900 = 900L;

  private static final int DURATION_LEN = 10;

  private static final int PERCENT_LEN = 6;

  private static final int SPEED_LEN = 10;

  private static final int TIME_LEN = 10;

  private static final int TOTAL_LEN = 15;

  private long total;

  private boolean hasTotal;

  private Instant startTime;

  private Instant endTime;

  private AtomicLong numProcessed;

  private Instant lastPrintTime;

  private final AtomicBoolean finished = new AtomicBoolean(false);

  private Duration totalElapsedTime;

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
    sb.append(formatText("average", SPEED_LEN)).append(formatText("current", SPEED_LEN))
        .append(formatText("time", DURATION_LEN));
    if (hasTotal) {
      sb.append(formatText("time", DURATION_LEN)).append(formatText("finish", TIME_LEN));
    }
    sb.append('\n');

    // third header line
    sb.append(StringUtil.formatText("total", TOTAL_LEN));
    if (hasTotal) {
      sb.append(formatText("%", PERCENT_LEN));
    }
    sb.append(formatText("speed", SPEED_LEN)).append(formatText("speed", SPEED_LEN))
      .append(formatText("spent", DURATION_LEN));
    if (hasTotal) {
      sb.append(formatText("left", DURATION_LEN)).append(formatText("at", TIME_LEN));
    }
    sb.append('\n');

    System.out.println(sb);
    System.out.flush();
  } // method printHeader

  public void finish() {
    finished.set(true);
    endTime = Instant.now();
    totalElapsedTime = Duration.between(startTime, endTime);

    totalAverageSpeed = 0;
    if (totalElapsedTime.toMillis() > 0) {
      totalAverageSpeed = (int) averagePerSecond(numProcessed.get(), totalElapsedTime.toMillis());
    }
  }

  public void printTrailer() {
    finish();
    printStatus(true);
    StringBuilder sb = new StringBuilder().append('\n');

    final int lineLength = getLineLength();
    for (int i = 0; i < lineLength; i++) {
      sb.append('-');
    }

    System.out.println(sb);
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
    startTime = Instant.now();
    numProcessed = new AtomicLong(0);
    lastPrintTime = Instant.ofEpochMilli(0);
    measureDeque.clear();
    measureDeque.add(new MeasurePoint(startTime, 0));

    hasTotal = total > 0;
  }

  public Instant startTime() {
    return startTime;
  }

  public Instant endTime() {
    return endTime;
  }

  public long addNumProcessed(long numProcessed) {
    return this.numProcessed.addAndGet(numProcessed);
  }

  public void printStatus() {
    printStatus(false);
  }

  private void printStatus(boolean forcePrint) {
    final Instant now = Instant.now();
    final long tmpNumProcessed = numProcessed.get();

    if (!forcePrint && Duration.between(lastPrintTime, now).toMillis() < MS_900) {
      return;
    }

    measureDeque.addLast(new MeasurePoint(now, numProcessed.get()));
    lastPrintTime = now;

    int numMeasurePoints = measureDeque.size();
    MeasurePoint referenceMeasurePoint = (numMeasurePoints > 10) ? measureDeque.removeFirst()
        : measureDeque.getFirst();

    StringBuilder sb = new StringBuilder("\r");

    // processed number
    sb.append(StringUtil.formatAccount(tmpNumProcessed, TOTAL_LEN));

    // processed percent
    if (hasTotal) {
      int percent = (int) (tmpNumProcessed * 100 / total);
      sb.append(formatText(percent + "%", PERCENT_LEN));
    }

    // average speed
    long averageSpeed = 0;
    long elapsedTimeMilli = Duration.between(startTime, now).toMillis();
    if (elapsedTimeMilli > 0) {
      averageSpeed = averagePerSecond(tmpNumProcessed, elapsedTimeMilli);
    }
    sb.append(StringUtil.formatAccount(averageSpeed, SPEED_LEN));

    // current speed
    long currentSpeed = 0;
    long t2Milli = Duration.between(referenceMeasurePoint.measureTime, now).toMillis();
    if (t2Milli > 0) {
      currentSpeed = averagePerSecond(tmpNumProcessed - referenceMeasurePoint.measureAccount, t2Milli);
    }
    sb.append(StringUtil.formatAccount(currentSpeed, SPEED_LEN));

    // elapsed time
    sb.append(StringUtil.formatTime(elapsedTimeMilli / 1000, DURATION_LEN));

    // remaining time and finish at
    if (hasTotal) {
      long remaingTimeSeconds = -1;
      if (currentSpeed > 0) {
        remaingTimeSeconds = (total - tmpNumProcessed) / currentSpeed;
      }

      Instant finishAt = null;
      if (remaingTimeSeconds != -1) {
        finishAt = now.plus(remaingTimeSeconds, ChronoUnit.SECONDS);
      }

      if (remaingTimeSeconds < 1) {
        sb.append(formatText("--", DURATION_LEN)).append(formatText("--", TIME_LEN));
      } else {
        sb.append(StringUtil.formatTime(remaingTimeSeconds, DURATION_LEN)).append(buildDateTime(finishAt));
      }
    }

    System.out.print(sb);
    System.out.flush();
  } // method printStatus

  public Duration totalElapsedTime() {
    if (finished.get()) {
      return totalElapsedTime;
    }

    return Duration.between(startTime, Instant.now());
  }

  public int totalAverageSpeed() {
    if (finished.get()) {
      return totalAverageSpeed;
    }

    Duration elapsedTime = Duration.between(startTime, Instant.now());
    int averageSpeed = 0;
    if (!elapsedTime.isZero()) {
      averageSpeed = (int) averagePerSecond(numProcessed.get(), elapsedTime.toMillis());
    }
    return averageSpeed;
  }

  private static String formatText(String text, int minLen) {
    return StringUtil.formatText(text, minLen);
  }

  private static String buildDateTime(Instant time) {
    ZonedDateTime cal = time.atZone(ZoneId.systemDefault());

    StringBuilder sb = new StringBuilder();
    int hour = cal.getHour();
    if (hour < 10) {
      sb.append('0');
    }
    sb.append(hour);

    int minute = cal.getMinute();
    sb.append(":");
    if (minute < 10) {
      sb.append('0');
    }
    sb.append(minute);

    int second = cal.getSecond();
    sb.append(":");
    if (second < 10) {
      sb.append('0');
    }
    sb.append(second);

    ZonedDateTime now = ZonedDateTime.now();
    ZonedDateTime midNight = ZonedDateTime.of(now.getYear(), now.getMonthValue(), now.getDayOfMonth(),
        0, 0, 0, 0, now.getZone());
    long midNightSec = midNight.toInstant().getEpochSecond();
    long days = Duration.between(midNight, time).toDays();
    if (days > 0) {
      sb.append('+').append(days > 9 ? "x" : Long.toString(days));
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

    len += SPEED_LEN + SPEED_LEN + DURATION_LEN;

    if (hasTotal) {
      len += DURATION_LEN + TIME_LEN;
    }

    return len;
  }

  private static long averagePerSecond(long value, long millis) {
    return value * 1000 / millis;
  }

}
