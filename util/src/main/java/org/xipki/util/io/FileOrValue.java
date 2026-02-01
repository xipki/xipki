// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.io;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.misc.StringUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration consisting either file path or the text content.
 *
 * @author Lijun Liao (xipki)
 */

public class FileOrValue implements JsonEncodable {

  private String file;

  private String value;

  protected FileOrValue(String file, String value) {
    Args.exactOne(file, "file", value, "value");
    this.file = file;
    this.value = value;
  }

  public static FileOrValue ofFile(String fileName) {
    return new FileOrValue(fileName, null);
  }

  public static FileOrValue ofValue(String value) {
    return new FileOrValue(null, value);
  }

  public void setFile(String file) {
    this.file = Args.notBlank(file, "file");
    this.value = null;
  }

  public String file() {
    return file;
  }

  public void setValue(String value) {
    this.value = Args.notNull(value, "value");
    this.file = null;
  }

  public String value() {
    return value;
  }

  public String readContent() throws IOException {
    if (value != null) {
      return value;
    }

    return StringUtil.toUtf8String(IoUtil.read(IoUtil.detectPath(file)));
  }

  public String toString() {
    if (file != null) {
      return "file:" + file;
    } else if (value != null) {
      return "value:" + value.substring(0, Math.min(6, value.length())) + "...";
    } else {
      return "<NULL>";
    }
  }

  public static List<FileOrValue> parseList(JsonList json)
      throws CodecException {
    if (json == null) {
      return null;
    }

    List<FileOrValue> ret = new ArrayList<>();
    for (JsonMap m : json.toMapList()) {
      ret.add(parse(m));
    }
    return ret;
  }

  public static FileOrValue[] parseArray(JsonList json)
      throws CodecException {
    List<FileOrValue> list = parseList(json);
    return list == null ? null : list.toArray(new FileOrValue[0]);
  }

  public static FileOrValue parse(JsonMap json) throws CodecException {
    return json == null ? null
        : new FileOrValue(json.getString("file"), json.getString("value"));
  }

  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    if (file != null) {
      ret.put("file", file);
    }

    if (value != null) {
      ret.put("value", value);
    }
    return ret;
  }

  public static JsonList toJson(List<FileOrValue> values) {
    if (values == null) {
      return null;
    }

    return toJson(values.toArray(new FileOrValue[0]));
  }

  public static JsonList toJson(FileOrValue[] values) {
    if (values == null) {
      return null;
    }

    JsonList ret = new JsonList();
    for (FileOrValue v : values) {
      ret.add(v.toCodec());
    }
    return ret;
  }

}
