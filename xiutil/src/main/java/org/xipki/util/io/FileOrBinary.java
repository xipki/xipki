// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.io;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.Hex;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Configuration consisting either the file path or the binary content.
 *
 * @author Lijun Liao (xipki)
 */

public class FileOrBinary implements JsonEncodable {

  private String file;

  private byte[] binary;

  private FileOrBinary(String file, byte[] binary) {
    Args.exactOne(file, "file", binary, "binary");
    this.file = file;
    this.binary = binary;
  }

  public static FileOrBinary ofFile(String fileName) {
    return new FileOrBinary(fileName, null);
  }

  public static FileOrBinary ofBinary(byte[] binary) {
    return new FileOrBinary(null, binary);
  }

  public void setFile(String file) {
    this.file = Args.notBlank(file, "file");
    this.binary = null;
  }

  public String getFile() {
    return file;
  }

  public void setBinary(byte[] binary) {
    this.binary = Args.notNull(binary, "binary");
    this.file = null;
  }

  public byte[] getBinary() {
    return binary;
  }

  public byte[] readContent() throws IOException {
    if (binary != null) {
      return binary;
    }

    return IoUtil.read(IoUtil.detectPath(file));
  }

  @Override
  public String toString() {
    if (file != null) {
      return "file:" + file;
    } else if (binary != null) {
      return "binary:" + Hex.encode(
          Arrays.copyOf(binary, Math.min(6, binary.length))) + "...";
    } else {
      return "<NULL>";
    }
  }

  public static List<FileOrBinary> parseList(JsonList json)
      throws CodecException {
    if (json == null) {
      return null;
    }

    List<FileOrBinary> ret = new ArrayList<>();
    for (JsonMap m : json.toMapList()) {
      ret.add(parse(m));
    }
    return ret;
  }

  public static FileOrBinary[] parseArray(JsonList json)
      throws CodecException {
    List<FileOrBinary> list = parseList(json);
    return list == null ? null : list.toArray(new FileOrBinary[0]);
  }

  public static FileOrBinary parse(JsonMap json) throws CodecException {
    return json == null ? null
        : new FileOrBinary(json.getString("file"), json.getBytes("binary"));
  }

  @Override
  public JsonMap toCodec() {
    JsonMap ret = new JsonMap();
    if (file != null) {
      ret.put("file", file);
    }

    if (binary != null) {
      ret.put("binary", binary);
    }
    return ret;
  }

  public static JsonList toJson(List<FileOrBinary> values) {
    if (values == null) {
      return null;
    }

    return toJson(values.toArray(new FileOrBinary[0]));
  }

  public static JsonList toJson(FileOrBinary[] values) {
    if (values == null) {
      return null;
    }

    JsonList ret = new JsonList();
    for (FileOrBinary v : values) {
      ret.add(v.toCodec());
    }
    return ret;
  }

}
