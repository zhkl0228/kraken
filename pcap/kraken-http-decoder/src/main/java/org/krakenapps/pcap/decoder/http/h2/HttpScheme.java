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
public enum HttpScheme
{
    HTTP("http"),
    HTTPS("https"),
    WS("ws"),
    WSS("wss");

    /* ------------------------------------------------------------ */
    public final static Map<String, HttpScheme> CACHE= new HashMap<String, HttpScheme>();
    static
    {
        for (HttpScheme version : HttpScheme.values())
            CACHE.put(version.asString(),version);
    }

    private final String _string;
    private final ByteBuffer _buffer;

    /* ------------------------------------------------------------ */
    HttpScheme(String s)
    {
        _string=s;
        try {
            _buffer=ByteBuffer.wrap(s.getBytes("ISO-8859-1"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /* ------------------------------------------------------------ */
    public ByteBuffer asByteBuffer()
    {
        return _buffer.asReadOnlyBuffer();
    }

    /* ------------------------------------------------------------ */
    public boolean is(String s)
    {
        return _string.equalsIgnoreCase(s);
    }

    public String asString()
    {
        return _string;
    }

    /* ------------------------------------------------------------ */
    @Override
    public String toString()
    {
        return _string;
    }

}