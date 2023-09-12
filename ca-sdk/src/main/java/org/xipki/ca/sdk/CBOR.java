// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import java.io.*;
import java.nio.file.Path;
import java.time.Instant;

/**
 * CBOR util class
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class CBOR {

  private static class InstantSerializer extends JsonSerializer<Instant> {

    @Override
    public void serialize(Instant instant, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
        throws IOException {
      jsonGenerator.writeNumber(instant.toEpochMilli());
    }
  }

  private static class InstantDeserializer extends JsonDeserializer<Instant> {

    @Override
    public Instant deserialize(JsonParser jsonParser, DeserializationContext deserializationContext)
        throws IOException, JacksonException {
      return Instant.ofEpochMilli(jsonParser.getValueAsLong());
    }

  }

  public static class XiJsonModule extends SimpleModule {

    public  static XiJsonModule INSTANCE = new XiJsonModule();
    public XiJsonModule() {
      addSerializer(Instant.class,   new InstantSerializer());
      addDeserializer(Instant.class, new InstantDeserializer());
    }

  }

  private static final ObjectMapper cbor;
  static {
    cbor = new ObjectMapper(new CBORFactory())
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    cbor.registerModule(XiJsonModule.INSTANCE);
  }

  public static <T> T parseObject(byte[] cborBytes, Class<T> classOfT) {
    try {
      return cbor.readValue(cborBytes, classOfT);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T parseObject(Path jsonFilePath, Class<T> classOfT) throws IOException {
    return cbor.readValue(jsonFilePath.toFile(), classOfT);
  }

  public static <T> T parseObject(File jsonFile, Class<T> classOfT) throws IOException {
    return cbor.readValue(jsonFile, classOfT);
  }

  /**
   * The specified stream is closed after this method returns.
   */
  public static <T> T parseObjectAndClose(InputStream jsonInputStream, Class<T> classOfT) throws IOException {
    try (Reader reader = new InputStreamReader(jsonInputStream)) {
      return cbor.readValue(reader, classOfT);
    }
  }

  public static byte[] toBytes(Object obj) {
    try {
      return cbor.writeValueAsBytes(obj);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * The specified stream remains open after this method returns.
   */
  public static void writeCBOR(Object object, OutputStream outputStream) {
    try {
      cbor.writeValue(outputStream, object);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
