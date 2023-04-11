//
//  ========================================================================
//  Copyright (c) 1995-2017 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.krakenapps.pcap.decoder.http.h2;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;


/* ------------------------------------------------------------------------------- */
/**
 */
public enum HttpMethod
{
    GET,
    POST,
    HEAD,
    PUT,
    OPTIONS,
    DELETE,
    TRACE,
    CONNECT,
    MOVE,
    PROXY,
    PRI;

    /* ------------------------------------------------------------ */
    public final static Map<String, HttpMethod> CACHE= new HashMap<String, HttpMethod>();
    static
    {
        for (HttpMethod method : HttpMethod.values())
            CACHE.put(method.toString(),method);
    }

    /* ------------------------------------------------------------ */
    private final ByteBuffer _buffer;
    private final byte[] _bytes;

    /* ------------------------------------------------------------ */
    HttpMethod()
    {
        try {
            _bytes=toString().getBytes("ISO-8859-1");
            _buffer=ByteBuffer.wrap(_bytes);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /* ------------------------------------------------------------ */
    public byte[] getBytes()
    {
        return _bytes;
    }

    /* ------------------------------------------------------------ */
    public boolean is(String s)
    {
        return toString().equalsIgnoreCase(s);
    }

    /* ------------------------------------------------------------ */
    public ByteBuffer asBuffer()
    {
        return _buffer.asReadOnlyBuffer();
    }

    /* ------------------------------------------------------------ */
    public String asString()
    {
        return toString();
    }

    /* ------------------------------------------------------------ */
    /**
     * Converts the given String parameter to an HttpMethod
     * @param method the String to get the equivalent HttpMethod from
     * @return the HttpMethod or null if the parameter method is unknown
     */
    public static HttpMethod fromString(String method)
    {
        return CACHE.get(method);
    }
}