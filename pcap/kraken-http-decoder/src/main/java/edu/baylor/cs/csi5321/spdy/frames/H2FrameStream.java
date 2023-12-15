package edu.baylor.cs.csi5321.spdy.frames;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 *
 * @author ICPCDev
 */
public abstract class H2FrameStream extends H2ControlFrame {

    protected int streamId;

    public int getStreamId() {
        return streamId;
    }

    public void setStreamId(int streamId) throws H2Exception {
        if(streamId < 0) {
            throw new H2Exception("StreamId must be 31-bit value in integer, thus it must not be negative value");
        }
        this.streamId = streamId;
        
    }

    public H2FrameStream(int streamId, boolean controlBit, byte flags, int length) throws H2Exception {
        super(controlBit, flags, length);
        setStreamId(streamId);
    }

    public H2FrameStream(boolean controlBit, byte flags, int length) throws H2Exception {
        super(controlBit, flags, length);
    }

    @Override
    public byte[] encode() throws H2Exception {
        byte[] header = super.encode();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bout);
        try {
            bout.write(header);
            dos.writeInt(getStreamId() & 0x7FFFFFFF);
            dos.close();
        } catch (IOException ex) {
            throw new H2Exception(ex);
        }
        return bout.toByteArray();
    }

    @Override
    public H2Frame decode(DataInputStream is) throws H2Exception {
        try {
            int stream = is.readInt();
            setStreamId(stream & H2Util.MASK_STREAM_ID_HEADER);
            return this;
        } catch (Exception ex) {
            throw new H2Exception(ex);
        }
    }
    
    @Override
    public void setLength(int length) throws H2Exception {
        super.setLength(length); //+4
    }

    @Override
    public boolean equals(Object obj) {
        if(!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final H2FrameStream other = (H2FrameStream) obj;
        return this.streamId == other.streamId;
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
