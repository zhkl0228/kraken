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

/* ------------------------------------------------------------ */
public class StaticTableHttpField extends HttpField
{
    private final Object _value;

    public StaticTableHttpField(HttpHeader header, String name, String valueString, Object value)
    {
        super(header,name,valueString);
        if (value==null)
            throw new IllegalArgumentException();
        _value=value;
    }

    public Object getStaticValue()
    {
        return _value;
    }

    @Override
    public String toString()
    {
        return super.toString()+"(evaluated)";
    }
}