// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.datasource;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.io.FileOrValue;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration of DataSource.
 *
 * @author Lijun Liao (xipki)
 */
public class DataSourceConf {

  private final String name;

  private final FileOrValue conf;

  public DataSourceConf(String name, FileOrValue conf) {
    this.name = Args.notBlank(name, "name");
    this.conf = Args.notNull(conf, "conf");
  }

  public FileOrValue getConf() {
    return conf;
  }

  public String getName() {
    return name;
  }

  public static List<DataSourceConf> parseList(JsonList json)
      throws CodecException {
    if (json == null) {
      return null;
    }

    List<DataSourceConf> ret = new ArrayList<>();
    for (JsonMap m : json.toMapList()) {
      ret.add(parse(m));
    }
    return ret;
  }

  public static DataSourceConf[] parseArray(JsonList json)
      throws CodecException {
    List<DataSourceConf> list = parseList(json);
    return list == null ? null : list.toArray(new DataSourceConf[0]);
  }

  public static DataSourceConf parse(JsonMap json) throws CodecException {
    return json == null ? null
        : new DataSourceConf(json.getNnString("name"),
              FileOrValue.parse(json.getMap("conf")));
  }

}

