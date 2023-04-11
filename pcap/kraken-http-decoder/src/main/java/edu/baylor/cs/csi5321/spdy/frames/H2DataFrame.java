package edu.baylor.cs.csi5321.spdy.frames;

import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.util.HexFormatter;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 *
 * @author Lukas Camra
 */
public class H2DataFrame extends H2Frame {

    private int streamId;
    private byte[] data = new byte[0];

    public H2DataFrame(int streamId, byte[] data, boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
        setStreamId(streamId);
        this.data = data;
    }

    public H2DataFrame(int streamId, boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
        setStreamId(streamId);
    }

    public int getStreamId() {
        return streamId;
    }

    public void setStreamId(int streamId) throws SpdyException {
        if(streamId < 0) {
            throw new SpdyException("Stream ID must be 31-bit number within 32-bit integer, that is, it must not be a negative number");
        }
        this.streamId = streamId;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    @Override
    public void setControlBit(boolean controlBit) throws SpdyException {
        if (isControlBit()) {
            throw new SpdyException("For data frame the control bit must be 0");
        }
        super.controlBit = controlBit;
    }

    @Override
    public byte[] encode() throws SpdyException {
        try {
            setLength(data == null ? 0 : data.length);
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bout);
            if (isControlBit()) {
                throw new SpdyException("For data frame the control bit must be 0");
            }
            dos.writeInt((getControlBitNumber() << 31 | (getStreamId() & SpdyUtil.MASK_STREAM_ID_HEADER)));
            dos.writeInt(getFlags() << 24 | (getLength() & SpdyUtil.MASK_LENGTH_HEADER));
            dos.write(data);
            dos.close();
            return bout.toByteArray();
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }
    }

    @Override
    public H2Frame decode(DataInputStream is) throws SpdyException {
        try {
            byte[] dat = new byte[getLength()];
            is.readFully(dat);
            this.data = dat;
            return this;
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }
    }

    @Override
    public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws SpdyException {
        int padLength = hasFlag(FLAG_PADDED) ? buffer.get() & 0xff : 0;
        this.data = new byte[buffer.remaining() - padLength];
        buffer.get(data);
        return this;
    }

    @Override
    public Byte[] getValidFlags() {
        return new Byte[] { FLAG_END_STREAM, FLAG_PADDED };
    }

    @Override
    public boolean equals(Object obj) {
        if(!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final H2DataFrame other = (H2DataFrame) obj;
        if (this.streamId != other.streamId) {
            return false;
        }
        return Arrays.equals(this.data, other.data);
    }

    @Override
    public int hashCode() {
        int hash = 5 * super.hashCode();
        hash = 31 * hash + this.streamId;
        hash = 31 * hash + Arrays.hashCode(this.data);
        return hash;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [streamId=" + streamId + ", flags=" + getFlags() + ", data=" + HexFormatter.encodeHexString(data) + "]";
    }
    
}
