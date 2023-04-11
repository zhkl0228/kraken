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

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;

public class AuthorityHttpField extends HostPortHttpField
{
    public final static String AUTHORITY = HttpSessionImpl.STATIC_TABLE[1][0];

    public AuthorityHttpField(String authority)
    {
        super(HttpHeader.C_AUTHORITY,AUTHORITY,authority);
    }

    @Override
    public String toString()
    {
        return String.format("%s(preparsed h=%s p=%d)",super.toString(),getHost(),getPort());
    }
}