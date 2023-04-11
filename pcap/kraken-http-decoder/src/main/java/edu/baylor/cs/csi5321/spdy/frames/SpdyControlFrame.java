package edu.baylor.cs.csi5321.spdy.frames;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 *
 * @author Lukas Camra
 */
public abstract class SpdyControlFrame extends H2Frame {

    public static final short VERSION_CONTROL_FRAME = 3;
    public static final int HEADER_LENGTH = 4;

    public SpdyControlFrame(boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
    }

    public abstract SpdyControlFrameType getType();

    public short getVersion() {
        return VERSION_CONTROL_FRAME;
    }

    @Override
    public void setControlBit(boolean controlBit) throws SpdyException {
        if (!controlBit) {
            throw new SpdyException("Control bit for control frames must be 1");
        }
        super.controlBit = controlBit;
    }

    @Override
    public byte[] encode() throws SpdyException {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream(HEADER_LENGTH);
            DataOutputStream dos = new DataOutputStream(bout);
            dos.writeInt(getControlBitNumber() << 31 | ((getVersion() & 0x7FFF) << 16) | getType().getValue());
            dos.writeInt(getFlags() << 24 | (getLength() & 0x00FFFFFF));
            dos.close();
            return bout.toByteArray();
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }
    }
}
