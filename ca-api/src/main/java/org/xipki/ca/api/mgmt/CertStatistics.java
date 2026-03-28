// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Statistics data of issued certificates.
 *
 * @author Lijun Liao (xipki)
 */
public class CertStatistics implements JsonEncodable {

  public static class YearMonth implements JsonEncodable {
    private final int year;
    private final int month;

    public YearMonth(int year, int month) {
      this.year = year;
      this.month = month;
    }

    public int getYear() {
      return year;
    }

    public int getMonth() {
      return month;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("year", year);
      ret.put("month", month);
      return ret;
    }

    public static YearMonth parse(JsonMap json) throws CodecException {
      return new YearMonth(json.getNnInt("year"), json.getNnInt("month"));
    }

  }

  public static class ByMonth implements JsonEncodable {

    /**
     * Month, from 1 to 12
     */
    private final int month;
    private final int total;

    public ByMonth(int month, int total) {
      this.month = month;
      this.total = total;
    }

    public int getMonth() {
      return month;
    }

    public int getTotal() {
      return total;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("month", month);
      ret.put("total", total);
      return ret;
    }

    public static ByMonth parse(JsonMap json) throws CodecException {
      return new ByMonth(json.getNnInt("month"), json.getNnInt("total"));
    }

  }

  public static class ByYear implements JsonEncodable {
    private final int year;
    private final int total;
    private final List<ByMonth> months;

    public ByYear(int year, int total, List<ByMonth> months) {
      this.year = year;
      this.total = total;
      this.months = Args.notNull(months, "months");
    }

    public int getYear() {
      return year;
    }

    public int getTotal() {
      return total;
    }

    public List<ByMonth> getMonths() {
      return months;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("year", year);
      ret.put("total", total);
      ret.putEncodables("months", months);
      return ret;
    }

    public static ByYear parse(JsonMap json) throws CodecException {
      int year = json.getNnInt("year");
      int total = json.getNnInt("total");
      JsonList jsonList = json.getNnList("months");
      List<ByMonth> months = new ArrayList<>(jsonList.size());
      for (JsonMap m : jsonList.toMapList()) {
        months.add(ByMonth.parse(m));
      }
      return new ByYear(year, total, months);
    }

  }

  public static class Summary implements JsonEncodable {

    private Map<String, Integer> byCa;

    private Map<String, Integer> byProfile;

    private Map<String, Integer> byRequestor;

    public Map<String, Integer> getByCa() {
      return byCa;
    }

    public void setByCa(Map<String, Integer> byCa) {
      this.byCa = byCa;
    }

    public Map<String, Integer> getByProfile() {
      return byProfile;
    }

    public void setByProfile(Map<String, Integer> byProfile) {
      this.byProfile = byProfile;
    }

    public Map<String, Integer> getByRequestor() {
      return byRequestor;
    }

    public void setByRequestor(Map<String, Integer> byRequestor) {
      this.byRequestor = byRequestor;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      if (byCa != null) {
        ret.put("byCa", toJson(byCa));
      }

      if (byRequestor != null) {
        ret.put("byRequestor", toJson(byRequestor));
      }

      if (byProfile != null) {
        ret.put("byProfile", toJson(byProfile));
      }

      return ret;
    }

    public static Summary parse(JsonMap json) throws CodecException {
      Summary ret = new Summary();
      JsonMap map = json.getMap("byCa");
      if (map != null) {
        ret.setByCa(fromJson(map));
      }

      map = json.getMap("byRequestor");
      if (map != null) {
        ret.setByRequestor(fromJson(map));
      }

      map = json.getMap("byProfile");
      if (map != null) {
        ret.setByProfile(fromJson(map));
      }

      return ret;
    }

    private static JsonMap toJson(Map<String, Integer> map) {
      JsonMap ret = new JsonMap();
      for (Map.Entry<String, Integer> entry : map.entrySet()) {
        ret.put(entry.getKey(), entry.getValue());
      }
      return ret;
    }

    private static Map<String, Integer> fromJson(JsonMap json) throws CodecException {
      Map<String, Integer> ret = new HashMap<>(json.size());
      for (String key : json.getKeys()) {
        ret.put(key, json.getNnInt(key));
      }
      return ret;
    }
  }

  private final YearMonth from;
  private final YearMonth to;

  private final Summary summary;

  private final List<ByYear> details;

  public CertStatistics(YearMonth from, YearMonth to, Summary summary, List<ByYear> details) {
    this.from = Args.notNull(from, "from");
    this.to = Args.notNull(to, "to");
    this.summary = Args.notNull(summary, "summary");
    this.details = Args.notNull(details, "details");
  }

  public YearMonth getFrom() {
    return from;
  }

  public YearMonth getTo() {
    return to;
  }

  public Summary getSummary() {
    return summary;
  }

  public List<ByYear> getDetails() {
    return details;
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    ret.put("from", from);
    ret.put("to", to);
    ret.put("summary", summary);
    ret.putEncodables("details", details);
    return ret;
  }

  public static CertStatistics parse(JsonMap json) throws CodecException {
    YearMonth from = YearMonth.parse(json.getNnMap("from"));
    YearMonth to = YearMonth.parse(json.getNnMap("to"));
    Summary summary = Summary.parse(json.getNnMap("summary"));
    JsonList list = json.getNnList("details");
    List<ByYear> details = new ArrayList<>(list.size());
    for (JsonMap m : list.toMapList()) {
      details.add(ByYear.parse(m));
    }
    return new CertStatistics(from, to, summary, details);
  }

}
