package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;

import java.io.DataInputStream;
import java.nio.ByteBuffer;

/**
 *
 * @author Lukas Camra
 */
public class H2FrameRstStream extends SpdyFrameStream {

    public enum ErrorCode {
        NO_ERROR,
        PROTOCOL_ERROR,
        INTERNAL_ERROR,
        FLOW_CONTROL_ERROR,
        SETTINGS_TIMEOUT,
        STREAM_CLOSED,
        FRAME_SIZE_ERROR,
        REFUSED_STREAM,
        CANCEL,
        COMPRESSION_ERROR,
        CONNECT_ERROR,
        ENHANCE_YOUR_CALM,
        INADEQUATE_SECURITY,
        HTTP_1_1_REQUIRED
    }

    private static final int LENGTH = 8;
    private ErrorCode statusCode;

    public ErrorCode getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(ErrorCode statusCode) {
        this.statusCode = statusCode;
    }

    public H2FrameRstStream(int streamId, boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
        this.streamId = streamId;
    }

    @Override
    public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws SpdyException {
        int statusCode = buffer.getInt();
        for (ErrorCode errorCode : ErrorCode.values()) {
            if (errorCode.ordinal() == statusCode) {
                this.statusCode = errorCode;
                return;
            }
        }
        this.statusCode = ErrorCode.INTERNAL_ERROR;
    }

    @Override
    public SpdyControlFrameType getType() {
        return SpdyControlFrameType.RST_STREAM;
    }

    @Override
    public byte[] encode() throws SpdyException {
        throw new UnsupportedOperationException();
    }

    @Override
    public H2Frame decode(DataInputStream is) throws SpdyException {
        throw new UnsupportedOperationException();
    }
    
    @Override
    public int getLength() {
        return LENGTH;
    }

    @Override
    public boolean equals(Object obj) {
        if(!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final H2FrameRstStream other = (H2FrameRstStream) obj;
        return this.statusCode == other.statusCode;
    }

    @Override
    public int hashCode() {
        int hash = 7 * super.hashCode();
        hash = 29 * hash + this.statusCode.ordinal();
        return hash;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [streamId=" + streamId + ", statusCode=" + statusCode + "]";
    }
    
}
