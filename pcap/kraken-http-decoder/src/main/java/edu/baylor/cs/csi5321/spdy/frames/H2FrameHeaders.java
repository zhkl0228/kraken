package edu.baylor.cs.csi5321.spdy.frames;

import com.twitter.hpack.Decoder;
import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.util.HexFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 * @author Lukas Camra
 */
public class H2FrameHeaders extends H2FrameSynStream {

    private static final Logger log = LoggerFactory.getLogger(H2FrameHeaders.class);

    private H2NameValueBlock headers;
    private final Decoder hpackDecoder;

    public H2FrameHeaders(int streamId, boolean controlBit, byte flags, int length, Decoder hpackDecoder) throws H2Exception {
        super(streamId, controlBit, flags, length);
        this.hpackDecoder = hpackDecoder;
    }

    private Map<String, String> http2Headers;

    @Override
    public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws H2Exception {
        boolean hasPriority = hasFlag(FLAG_PRIORITY);
        int padLength = hasFlag(FLAG_PADDED) ? buffer.get() & 0xff : 0;
        int streamDependency = hasPriority ? buffer.getInt() : 0;
        boolean exclusive = streamDependency >>> 31 != 0;
        int associatedToStreamId = streamDependency & H2Util.MASK_STREAM_ID_HEADER;
        int weight = hasPriority ? buffer.get() & 0xff : 0;
        byte[] block = new byte[buffer.remaining() - padLength];
        buffer.get(block);
        http2Headers = new LinkedHashMap<>();
        try {
            hpackDecoder.decode(new ByteArrayInputStream(block), (name, value, sensitive) -> {
                String headerName = new String(name, StandardCharsets.UTF_8);
                String headerValue = new String(value, StandardCharsets.UTF_8);
                log.debug("addHeader headerName={}, value={}, sensitive={}", new Object[] {
                        headerName, headerValue, sensitive
                });
                http2Headers.put(headerName, headerValue);
            });
            hpackDecoder.endHeaderBlock();
        } catch (IOException e) {
            throw new H2Exception(e);
        }
        if (log.isDebugEnabled()) {
            log.debug("decode exclusive={}, associatedToStreamId=0x{}, weight={}, block={}, headers={}", new Object[] {
                    exclusive, Integer.toHexString(associatedToStreamId), weight, HexFormatter.encodeHexString(block),
                    http2Headers
            });
        }
        if(padLength > 0) {
            buffer.get(new byte[padLength]);
        }
    }

    @Override
    public H2ControlFrameType getType() {
        return H2ControlFrameType.HEADERS;
    }

    public Map<String, String> getHttp2Headers() {
        return http2Headers;
    }

    public void setHeaders(H2NameValueBlock headers) {
        this.headers = headers;
    }

    @Override
    public byte[] encode() throws H2Exception {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
            bout.write(headers.encode());
            byte[] body = bout.toByteArray();
            setLength(body.length + 4); //+4 for streamId
            byte[] header = super.encode();
            return H2Util.concatArrays(header, body);
        } catch (IOException ex) {
            throw new H2Exception(ex);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if(!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final H2FrameHeaders other = (H2FrameHeaders) obj;
        return this.headers.equals(other.headers);
    }

    @Override
    public int hashCode() {
        int hash = 3 * super.hashCode();
        hash = 29 * hash + this.headers.hashCode();
        return hash;
    }

    @Override
    public String toString() {
        return "H2FrameHeaders{" +
                "flags=0x" + Integer.toHexString(getFlags()) +
                ", headers=" + http2Headers +
                '}';
    }
}
