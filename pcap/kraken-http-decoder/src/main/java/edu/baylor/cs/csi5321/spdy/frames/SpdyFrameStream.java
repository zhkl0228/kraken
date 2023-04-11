package edu.baylor.cs.csi5321.spdy.frames;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 *
 * @author ICPCDev
 */
public abstract class SpdyFrameStream extends SpdyControlFrame {

    protected int streamId;

    public int getStreamId() {
        return streamId;
    }

    public void setStreamId(int streamId) throws SpdyException {
        if(streamId < 0) {
            throw new SpdyException("StreamId must be 31-bit value in integer, thus it must not be negative value");
        }
        this.streamId = streamId;
        
    }

    public SpdyFrameStream(int streamId, boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
        setStreamId(streamId);
    }

    public SpdyFrameStream(boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
    }

    @Override
    public byte[] encode() throws SpdyException {
        byte[] header = super.encode();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bout);
        try {
            bout.write(header);
            dos.writeInt(getStreamId() & 0x7FFFFFFF);
            dos.close();
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }
        return bout.toByteArray();
    }

    @Override
    public H2Frame decode(DataInputStream is) throws SpdyException {
        try {
            int stream = is.readInt();
            setStreamId(stream & SpdyUtil.MASK_STREAM_ID_HEADER);
            return this;
        } catch (Exception ex) {
            throw new SpdyException(ex);
        }
    }
    
    @Override
    public void setLength(int length) throws SpdyException {
        super.setLength(length); //+4
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
        final SpdyFrameStream other = (SpdyFrameStream) obj;
        if (this.streamId != other.streamId) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 7 * super.hashCode();
        hash = 61 * hash + this.streamId;
        return hash;
    }

	@Override
	public String toString() {
		return getClass().getSimpleName() + " [streamId=" + streamId + ", flags=" + getFlags() + "]";
	}
    
}
