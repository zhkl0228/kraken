package org.krakenapps.pcap.decoder.http.h2.entry;

import org.krakenapps.pcap.decoder.http.h2.HttpField;

public class Entry
{
    public final HttpField _field;
    public int _slot; // The index within it's array

    public Entry(HttpField field)
    {
        _field=field;
    }

    public int getSize()
    {
        String value = _field.getValue();
        return 32 + _field.getName().length() + (value == null ? 0 : value.length());
    }

    public HttpField getHttpField()
    {
        return _field;
    }

    public boolean isStatic()
    {
        return false;
    }

    public byte[] getStaticHuffmanValue()
    {
        return null;
    }

    public String toString()
    {
        return String.format("{%s,%d,%s,%x}",isStatic()?"S":"D",_slot,_field,hashCode());
    }
}