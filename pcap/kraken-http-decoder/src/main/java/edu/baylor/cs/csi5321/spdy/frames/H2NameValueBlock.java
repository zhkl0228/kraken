package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.util.HexFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
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
public class H2NameValueBlock {

    Map<String, String> pairs = new LinkedHashMap<String, String>();

    public Map<String, String> getPairs() {
        return pairs;
    }

    public byte[] encode() throws H2Exception {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bout);
            out.writeInt(pairs.size());
            for (String name : pairs.keySet()) {
                String value = pairs.get(name);
                byte[] nameByte = name.getBytes(H2Util.ENCODING);
                byte[] valueByte = value.getBytes(H2Util.ENCODING);
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
            compresser.setDictionary(H2Util.SPDY_dictionary_txt);
            compresser.finish();
            int resultLength = compresser.deflate(compressedContent);
            return Arrays.copyOfRange(compressedContent, 0, resultLength);
        } catch (IOException ex) {
            throw new H2Exception(ex);
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
            decompress.setDictionary(H2Util.SPDY_dictionary_txt);
            decompressedLength = decompress.inflate(buffer);
        }
        decompress.end();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(decompressedLength);
        bos.write(buffer, 0, decompressedLength);
        return bos.toByteArray();
    }
    
    private static final Logger log = LoggerFactory.getLogger(H2NameValueBlock.class);

    public static H2NameValueBlock decode(byte[] pairsByte) throws H2Exception {
        byte[] decompressedContent = null;
        try {
            //decompress the content
            H2NameValueBlock result = new H2NameValueBlock();
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
                    throw new H2Exception("Header name is a string with 0 length!");
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
                String name = new String(nameArr, H2Util.ENCODING);
                if (!H2Util.isLowerCase(name)) {
                    throw new H2Exception("Characters in header name must be all lower case!");
                }
                String value = new String(valueArr, H2Util.ENCODING);
                if (result.getPairs().containsKey(name)) {
                    throw new H2Exception("Duplicate header name: " + name);
                }
                result.getPairs().put(name, value);

            }
            return result;
        } catch (DataFormatException ex) {
            if(log.isDebugEnabled()) {
                log.debug("decode SpdyNameValueBlock failed. pairsByte=" + HexFormatter.encodeHexString(pairsByte));
            }
            throw new H2Exception(ex);
        } catch (IOException ex) {
            if(log.isDebugEnabled()) {
                log.debug("decode SpdyNameValueBlock failed. decompressedContent=" + HexFormatter.encodeHexString(decompressedContent));
            }
            throw new H2Exception(ex);
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
        final H2NameValueBlock other = (H2NameValueBlock) obj;
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
