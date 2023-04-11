package edu.baylor.cs.csi5321.spdy.frames;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author Lukas Camra
 */
public class H2FrameRstStream extends SpdyFrameStream {
	
	private static final int PROTOCOL_ERROR = 0x1;
	private static final int INVALID_STREAM = 0x2;
	private static final int REFUSED_STREAM = 0x3;
	private static final int UNSUPPORTED_VERSION = 0x4;
	private static final int CANCEL = 0x5;
	private static final int INTERNAL_ERROR = 0x6;
	private static final int FLOW_CONTROL_ERROR = 0x7;
	private static final int STREAM_IN_USE = 0x8;
	private static final int STREAM_ALREADY_CLOSED = 0x9;
	private static final int INVALID_CREDENTIALS = 0xa;
	private static final int FRAME_TOO_LARGE = 0xb;

    private static final int LENGTH = 8;
    public static final Integer[] STATUS_CODES = new Integer[]{ PROTOCOL_ERROR, INVALID_STREAM, REFUSED_STREAM, UNSUPPORTED_VERSION, CANCEL, INTERNAL_ERROR, FLOW_CONTROL_ERROR, STREAM_IN_USE, STREAM_ALREADY_CLOSED, INVALID_CREDENTIALS, FRAME_TOO_LARGE };
    private int statusCode;

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) throws SpdyException {
        if(!Arrays.asList(getValidStatusCodes()).contains(statusCode)) {
            throw new SpdyException("Invalid status code: " + statusCode);
        }
        this.statusCode = statusCode;
    }

    public H2FrameRstStream(int statusCode, int streamId, boolean controlBit, byte flags) throws SpdyException {
        super(streamId, controlBit, flags, LENGTH);
        this.statusCode = statusCode;
    }

    public H2FrameRstStream(boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
    }

    @Override
	public SpdyControlFrameType getType() {
		return SpdyControlFrameType.RST_STREAM;
	}

	@Override
    public byte[] encode() throws SpdyException {
        try {
            byte[] header = super.encode();
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bout);
            out.write(header);
            out.writeInt(statusCode);
            out.close();
            return bout.toByteArray();
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }
    }

    @Override
    public H2Frame decode(DataInputStream is) throws SpdyException {
        try {
            H2FrameRstStream f = (H2FrameRstStream) super.decode(is);
            int statusCode = is.readInt();
            f.setStatusCode(statusCode);
            return f;
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }

    }
    
    @Override
    public int getLength() {
        return LENGTH;
    }

    @Override
    public Byte[] getValidFlags() {
        return new Byte[]{};
    }
    
    public Integer[] getValidStatusCodes() {
        return STATUS_CODES;
    }

    @Override
    public boolean equals(Object obj) {
        if(!super.equals(obj)) {
            return false;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final H2FrameRstStream other = (H2FrameRstStream) obj;
        if (this.statusCode != other.statusCode) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 7 * super.hashCode();
        hash = 29 * hash + this.statusCode;
        return hash;
    }

	@Override
	public String toString() {
		return getClass().getSimpleName() + " [streamId=" + streamId + ", statusCode=" + statusCode + "]";
	}
    
}
