package org.krakenapps.pcap.decoder.http.h2.entry;

import org.krakenapps.pcap.decoder.http.h2.HttpField;
import org.krakenapps.pcap.decoder.http.h2.Huffman;
import org.krakenapps.pcap.decoder.http.h2.NBitInteger;

import java.nio.ByteBuffer;

public class StaticEntry extends Entry
{
    private final byte[] _huffmanValue;
    private final byte _encodedField;

    public StaticEntry(int index, HttpField field)
    {
        super(field);
        _slot=index;
        String value = field.getValue();
        if (value!=null && value.length()>0)
        {
            int huffmanLen = Huffman.octetsNeeded(value);
            int lenLen = NBitInteger.octectsNeeded(7,huffmanLen);
            _huffmanValue = new byte[1+lenLen+huffmanLen];
            ByteBuffer buffer = ByteBuffer.wrap(_huffmanValue);

            // Indicate Huffman
            buffer.put((byte)0x80);
            // Add huffman length
            NBitInteger.encode(buffer,7,huffmanLen);
            // Encode value
            Huffman.encode(buffer,value);
        }
        else
            _huffmanValue=null;

        _encodedField=(byte)(0x80|index);
    }

    @Override
    public boolean isStatic()
    {
        return true;
    }

    @Override
    public byte[] getStaticHuffmanValue()
    {
        return _huffmanValue;
    }

    public byte getEncodedField()
    {
        return _encodedField;
    }
}