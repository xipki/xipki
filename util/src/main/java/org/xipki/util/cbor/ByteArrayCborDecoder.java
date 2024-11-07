// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 *
 * Licensed under Apache License v2.0.
 */
package org.xipki.util.cbor;

import org.xipki.util.Args;

import java.io.ByteArrayInputStream;

public class ByteArrayCborDecoder extends CborDecoder {

    /**
     * Creates a new {@link ByteArrayCborDecoder} instance.
     * @param bytes the encoded cbor message.
     */
    public ByteArrayCborDecoder(byte[] bytes) {
        this(bytes, 0, bytes.length);
    }

    /**
     * Creates a new {@link ByteArrayCborDecoder} instance.
     * @param bytes the encoded cbor message.
     * @param offset offset of bytes.
     */
    public ByteArrayCborDecoder(byte[] bytes, int offset) {
        this(bytes, offset, bytes.length - offset);
    }

    /**
     * Creates a new {@link ByteArrayCborDecoder} instance.
     * @param bytes the encoded cbor message.
     * @param offset offset of bytes for the cbor message.
     * @param len length of the bytes for the cbor message.
     */
    public ByteArrayCborDecoder(byte[] bytes, int offset, int len) {
        super(new ByteArrayInputStream(bytes, Args.min(offset, "offset", 0), Args.min(len, "len", 0)));
    }

}
