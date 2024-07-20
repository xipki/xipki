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

import java.io.ByteArrayOutputStream;

public class ByteArrayCborEncoder extends CborEncoder {

    /**
     * Creates a new {@link ByteArrayCborEncoder} instance with default initial size 32.
     *
     */
    public ByteArrayCborEncoder() {
        this(32);
    }

    /**
     * Creates a new {@link ByteArrayCborEncoder} instance.
     * @param size the initial size.
     *
     */
    public ByteArrayCborEncoder(int size) {
        super(new ByteArrayOutputStream(Args.min(size, "size", 1)));
    }

    public byte[] toByteArray() {
        return ((ByteArrayOutputStream) m_os).toByteArray();
    }

}
