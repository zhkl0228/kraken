package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.util.HexFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 *
 * @author Lukas Camra
 */
public class H2FrameHeaders extends SpdyFrameSynStream {

    private static final Logger log = LoggerFactory.getLogger(H2FrameHeaders.class);

    private SpdyNameValueBlock headers;

    public H2FrameHeaders(int streamId, boolean controlBit, byte flags, int length) throws SpdyException {
        super(streamId, controlBit, flags, length);
    }

    @Override
    public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws SpdyException {
        boolean hasPriority = hasFlag(FLAG_PRIORITY);
        int padLength = hasFlag(FLAG_PADDED) ? buffer.get() & 0xff : 0;
        int streamDependency = hasPriority ? buffer.getInt() : 0;
        boolean exclusive = streamDependency >>> 31 != 0;
        int associatedToStreamId = streamDependency & SpdyUtil.MASK_STREAM_ID_HEADER;
        int weight = hasPriority ? buffer.get() & 0xff : 0;
        byte[] block = new byte[buffer.remaining() - padLength];
        buffer.get(block);
        this.headers = SpdyNameValueBlock.decodeHttp2(impl, ByteBuffer.wrap(block));
        if (log.isDebugEnabled()) {
            log.debug("decode exclusive={}, associatedToStreamId=0x{}, weight={}, block={}, headers={}", new Object[] {
                    exclusive, Integer.toHexString(associatedToStreamId), weight, HexFormatter.encodeHexString(block),
                    headers
            });
        }
        if(padLength > 0) {
            buffer.get(new byte[padLength]);
        }
        return this;
    }

    @Override
    public SpdyControlFrameType getType() {
        return SpdyControlFrameType.HEADERS;
    }

    public SpdyNameValueBlock getHeaders() {
        return headers;
    }

    public void setHeaders(SpdyNameValueBlock headers) {
        this.headers = headers;
    }

    @Override
    public byte[] encode() throws SpdyException {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            bout.write(headers.encode());
            byte[] body = bout.toByteArray();
            setLength(body.length + 4); //+4 for streamId
            byte[] header = super.encode();
            return SpdyUtil.concatArrays(header, body);
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }
    }

    @Override
    public Byte[] getValidFlags() {
        return new Byte[]{FLAG_END_STREAM, FLAG_END_HEADERS, FLAG_PADDED, FLAG_PRIORITY};
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
        return "SpdyFrameHeaders{" +
                "headers=" + headers +
                '}';
    }
}
