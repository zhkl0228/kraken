package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.decoder.http.h2.AuthorityHttpField;
import org.krakenapps.pcap.decoder.http.h2.HttpField;
import org.krakenapps.pcap.decoder.http.h2.HttpHeader;
import org.krakenapps.pcap.decoder.http.h2.Huffman;
import org.krakenapps.pcap.decoder.http.h2.NBitInteger;
import org.krakenapps.pcap.decoder.http.h2.entry.Entry;
import org.krakenapps.pcap.util.HexFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 *
 * @author Lukas Camra
 */
public class SpdyNameValueBlock {

    private static final Logger LOG = LoggerFactory.getLogger(SpdyNameValueBlock.class);

    private Map<String, String> pairs = new LinkedHashMap<String, String>();

    public Map<String, String> getPairs() {
        return pairs;
    }

    public void setPairs(Map<String, String> pairs) {
        this.pairs = pairs;
    }

    public SpdyNameValueBlock() {
    }

    public SpdyNameValueBlock(Map<String, String> pairs) {
        this.pairs = pairs;
    }

    public byte[] encode() throws SpdyException {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bout);
            out.writeInt(pairs.size());
            for (String name : pairs.keySet()) {
                String value = pairs.get(name);
                byte[] nameByte = name.getBytes(SpdyUtil.ENCODING);
                byte[] valueByte = value.getBytes(SpdyUtil.ENCODING);
                out.writeInt(nameByte.length);
                out.write(nameByte);
                out.writeInt(valueByte.length);
                out.write(valueByte);
            }
            byte[] contentArr = bout.toByteArray();
            //we need to compress it
            //let's create compressedContent buffer, that is extended by 100 for possible overhead
            byte[] compressedContent = new byte[contentArr.length + 100];
            Deflater compresser = new Deflater();
            //set up dictionary as stated in Spdy specification
            compresser.setInput(contentArr);
            compresser.setDictionary(SpdyUtil.SPDY_dictionary_txt);
            compresser.finish();
            int resultLength = compresser.deflate(compressedContent);
            return Arrays.copyOfRange(compressedContent, 0, resultLength);
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }

    }
    
    private static byte[] decompress1(byte[] pairsByte) throws DataFormatException {
        Inflater decompress = new Inflater();
        decompress.setInput(pairsByte, 0, pairsByte.length);

        //let's create buffer that is ten times of the size of pairs
        byte[] buffer = new byte[pairsByte.length * 10];
        int decompressedLength = 0;
        //first we need to call inflate in order to be able to set the dictionary
        decompressedLength = decompress.inflate(buffer);
        if (decompressedLength == 0 && decompress.needsDictionary()) {
            decompress.setDictionary(SpdyUtil.SPDY_dictionary_txt);
            decompressedLength = decompress.inflate(buffer);
        }
        decompress.end();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(decompressedLength);
        bos.write(buffer, 0, decompressedLength);
        return bos.toByteArray();
    }
    
    protected static byte[] decompress2(byte[] pairsByte) throws DataFormatException {
        Inflater decompress = new Inflater(true);
        decompress.setInput(pairsByte, 0, pairsByte.length);
        decompress.setDictionary(SpdyUtil.SPDY_dictionary_txt);

        //let's create buffer that is ten times of the size of pairs
        byte[] buffer = new byte[pairsByte.length * 10];
        int decompressedLength = 0;
        //first we need to call inflate in order to be able to set the dictionary
        decompressedLength = decompress.inflate(buffer);
        if (decompressedLength == 0 && decompress.needsDictionary()) {
            decompress.setDictionary(SpdyUtil.SPDY_dictionary_txt);
            decompressedLength = decompress.inflate(buffer);
        }
        decompress.end();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(decompressedLength);
        bos.write(buffer, 0, decompressedLength);
        return bos.toByteArray();
    }
    
    private static final Logger log = LoggerFactory.getLogger(SpdyNameValueBlock.class);

    public static SpdyNameValueBlock decodeHttp2(HttpSessionImpl impl, ByteBuffer buffer) throws SpdyException {
        SpdyNameValueBlock result = new SpdyNameValueBlock();
        while(buffer.hasRemaining()) {
            byte b = buffer.get();
            if (b < 0) {
                // 7.1 indexed if the high bit is set
                int index = NBitInteger.decode(buffer,7);
                Entry entry=impl.get(index);
                if (entry==null) {
                    throw new SpdyException("Unknown index "+index);
                }
                else
                {
                    if (LOG.isDebugEnabled())
                        LOG.debug("decode Idx {}",entry);
                    // emit
//                    _builder.emit(entry.getHttpField());
                    HttpField field = entry.getHttpField();
                    result.getPairs().put(field.getName(), field.getValue());
                }
            }
            else
            {
                // look at the first nibble in detail
                byte f= (byte)((b&0xF0)>>4);
                String name;
                HttpHeader header;
                String value;

                boolean indexed;
                int name_index;

                switch (f)
                {
                    case 2: // 7.3
                    case 3: // 7.3
                        // change table size
                        int size = NBitInteger.decode(buffer,5);
                        if (LOG.isDebugEnabled())
                            LOG.debug("decode resize="+size);
                        impl.resize(size);
                        continue;

                    case 0: // 7.2.2
                    case 1: // 7.2.3
                        indexed=false;
                        name_index=NBitInteger.decode(buffer,4);
                        break;

                    case 4: // 7.2.1
                    case 5: // 7.2.1
                    case 6: // 7.2.1
                    case 7: // 7.2.1
                        indexed=true;
                        name_index=NBitInteger.decode(buffer,6);
                        break;

                    default:
                        throw new IllegalStateException();
                }

                boolean huffmanName=false;

                // decode the name
                if (name_index>0)
                {
                    Entry name_entry=impl.get(name_index);
                    HttpField field = name_entry.getHttpField();
                    name=field.getName();
                    header=field.getHeader();
                }
                else
                {
                    huffmanName = (buffer.get()&0x80)==0x80;
                    int length = NBitInteger.decode(buffer,7);
//                    _builder.checkSize(length,huffmanName);
                    if (huffmanName)
                        name= Huffman.decode(buffer,length);
                    else
                        name=toASCIIString(buffer,length);
                    for (int i=0;i<name.length();i++)
                    {
                        char c=name.charAt(i);
                        if (c>='A'&&c<='Z')
                        {
                            throw new SpdyException("Uppercase header name");
                        }
                    }
                    header=HttpHeader.CACHE.get(name);
                }

                // decode the value
                boolean huffmanValue = (buffer.get()&0x80)==0x80;
                int length = NBitInteger.decode(buffer,7);
//                _builder.checkSize(length,huffmanValue);
                if (huffmanValue)
                    value=Huffman.decode(buffer,length);
                else
                    value=toASCIIString(buffer,length);

                // Make the new field
                HttpField field;
                if (header==null)
                {
                    // just make a normal field and bypass header name lookup
                    field = new HttpField(null,name,value);
                }
                else
                {
                    // might be worthwhile to create a value HttpField if it is indexed
                    // and/or of a type that may be looked up multiple times.
                    switch(header)
                    {
                        case C_STATUS:
                            if (indexed)
                                field = new HttpField.IntValueHttpField(header,name,value);
                            else
                                field = new HttpField(header,name,value);
                            break;

                        case C_AUTHORITY:
                            field = new AuthorityHttpField(value);
                            break;

                        case CONTENT_LENGTH:
                            if ("0".equals(value))
                                field = CONTENT_LENGTH_0;
                            else
                                field = new HttpField.LongValueHttpField(header,name,value);
                            break;
                        default:
                            field = new HttpField(header,name,value);
                            break;
                    }
                }

                if (LOG.isDebugEnabled())
                {
                    LOG.debug("decoded '{}' by {}/{}/{}",
                            new Object[] {
                                    field,
                                    name_index > 0 ? "IdxName" : (huffmanName ? "HuffName" : "LitName"),
                                    huffmanValue ? "HuffVal" : "LitVal",
                                    indexed ? "Idx" : ""
                            });
                }

                // emit the field
//                _builder.emit(field);
                result.getPairs().put(field.getName(), field.getValue());

                // if indexed
                if (indexed)
                {
                    // add to dynamic table
                    if (impl.add(field)==null)
                        throw new SpdyException("Indexed field value too large");
                }

            }
        }
        return result;
    }

    private final static HttpField.LongValueHttpField CONTENT_LENGTH_0 =
            new HttpField.LongValueHttpField(HttpHeader.CONTENT_LENGTH,0L);

    private static String toASCIIString(ByteBuffer buffer,int length)
    {
        StringBuilder builder = new StringBuilder(length);
        int position=buffer.position();
        int start=buffer.arrayOffset()+ position;
        int end=start+length;
        buffer.position(position+length);
        byte[] array=buffer.array();
        for (int i=start;i<end;i++)
            builder.append((char)(0x7f&array[i]));
        return builder.toString();
    }

    public static SpdyNameValueBlock decode(byte[] pairsByte) throws SpdyException {
        byte[] decompressedContent = null;
        try {
            //decompress the content
            SpdyNameValueBlock result = new SpdyNameValueBlock();
            decompressedContent = decompress1(pairsByte);
            if(log.isDebugEnabled()) {
                log.debug("SpdyNameValueBlock decompressedContent: " + HexFormatter.encodeHexString(decompressedContent));
            }
            //let's read the content
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(decompressedContent));
            int numberOfPairs = dis.readInt();
            for (int i = 0; i < numberOfPairs; i++) {
                int nameLength = dis.readInt();
                if (nameLength <= 0) {
                    throw new SpdyException("Header name is a string with 0 length!");
                }
//                if (nameLength > Math.pow(2, 24)) {
//                    throw new SpdyException("Maximum name length exceeded: " + nameLength);
//                }
                byte[] nameArr = new byte[nameLength];
                dis.readFully(nameArr);
                int valueLength = dis.readInt();
//                if (valueLength > Math.pow(2, 24)) {
//                    throw new SpdyException("Maximum value length exceeded: " + valueLength);
//                }
                byte[] valueArr = new byte[valueLength];
                dis.readFully(valueArr);
                String name = new String(nameArr, SpdyUtil.ENCODING);
                if (!SpdyUtil.isLowerCase(name)) {
                    throw new SpdyException("Characters in header name must be all lower case!");
                }
                String value = new String(valueArr, SpdyUtil.ENCODING);
                if (result.getPairs().containsKey(name)) {
                    throw new SpdyException("Duplicate header name: " + name);
                }
                result.getPairs().put(name, value);

            }
            return result;
        } catch (DataFormatException ex) {
            if(log.isDebugEnabled()) {
                log.debug("decode SpdyNameValueBlock failed. pairsByte=" + HexFormatter.encodeHexString(pairsByte));
            }
            throw new SpdyException(ex);
        } catch (IOException ex) {
            if(log.isDebugEnabled()) {
                log.debug("decode SpdyNameValueBlock failed. decompressedContent=" + HexFormatter.encodeHexString(decompressedContent));
            }
            throw new SpdyException(ex);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SpdyNameValueBlock other = (SpdyNameValueBlock) obj;
        return this.pairs.equals(other.pairs);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + this.pairs.hashCode();
        return hash;
    }

    @Override
    public String toString() {
        return "SpdyNameValueBlock{" +
                "pairs=" + pairs +
                '}';
    }
}
