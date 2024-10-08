package edu.baylor.cs.csi5321.spdy.frames;

import com.twitter.hpack.Decoder;
import org.krakenapps.pcap.decoder.http.impl.HttpSessionImpl;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.HexFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.nio.ByteBuffer;

/**
 *
 * @author Lukas Camra
 */
public abstract class H2Frame {

    private static final Logger log = LoggerFactory.getLogger(H2Frame.class);

    public static final byte FLAG_END_STREAM = 0x1;
    public static final byte FLAG_END_HEADERS = 0x4;
    public static final byte FLAG_PADDED = 0x8;
    public static final byte FLAG_PRIORITY = 0x20;

    protected boolean controlBit;
    private byte flags;
    private int length;

    public boolean isControlBit() {
        return controlBit;
    }

    public int getControlBitNumber() {
        return controlBit ? 1 : 0;
    }

    public abstract void setControlBit(boolean controlBit) throws H2Exception;

    public byte getFlags() {
        return flags;
    }

    public final void setFlags(byte flags) {
        this.flags = flags;
    }

    public final boolean hasFlag(byte flag) {
        return (flags & flag) != 0;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) throws H2Exception {
        if (length > Math.pow(2, 24)) {
            throw new H2Exception("Maximum length of 2^24 exceeded: " + length);
        }
        this.length = length;
    }

    public H2Frame(boolean controlBit, byte flags, int length) throws H2Exception {
        setControlBit(controlBit);
        setFlags(flags);
        setLength(length);
    }

    public abstract byte[] encode() throws H2Exception;

    /**
     * decode buffer
     * @return 返回 null 表示数据不够
     */
    public static H2Frame decodeBuffer(HttpSessionImpl impl, Buffer buffer, Decoder hpackDecoder) throws H2Exception {
        if(buffer.readableBytes() < 9) {
            return null;
        }
        buffer.mark();

        //read header of the packet
        int header = buffer.getInt();
        int length = (header >>> 8) & H2Util.MASK_LENGTH_HEADER;
        short type = (short) (header & 0xff);
        byte flags = buffer.get();
        int streamId = buffer.getInt() & H2Util.MASK_STREAM_ID_HEADER;

        if(buffer.readableBytes() < length) {
            buffer.reset();
            return null;
        }

        if (log.isDebugEnabled()) {
            log.debug("decodeBuffer type=0x{}, length={}, flags=0x{}, streamId=0x{}", new Object[]{Integer.toHexString(type), length, Integer.toHexString(flags), Integer.toHexString(streamId)});
        }

        byte[] packet = new byte[length];
        buffer.gets(packet);
        H2Frame frame;

        //according to type we will decide what concrete implementation is going to be created
        H2ControlFrameType typeEnum = H2ControlFrameType.getEnumTypeFromType(type);
        if (typeEnum == null) {
            throw new H2Exception("Control frame type is not supported, type: " + type);
        }
        switch (typeEnum) {
            case DATA:
                frame = new H2DataFrame(streamId, false, flags, length);
                break;
            case HEADERS:
                frame = new H2FrameHeaders(streamId, true, flags, length, hpackDecoder);
                break;
            case RST_STREAM:
                frame = new H2FrameRstStream(streamId, true, flags, length);
                break;
            case SETTINGS:
                frame = new H2FrameSettings(true, flags, length);
                break;
            case PING:
                frame = new H2FramePing(true, flags, length);
                break;
            case GOAWAY:
                frame = new H2FrameGoAway(streamId, true, flags, length);
                break;
            case WINDOW_UPDATE:
                frame = new H2FrameWindowUpdate(true, flags, length);
                break;
            case PRIORITY:
                frame = new H2PriorityFrame(streamId, true, flags, length);
                break;
            case PUSH_PROMISE:
            case CONTINUATION:
            default:
                throw new UnsupportedOperationException("typeEnum=" + typeEnum + ", streamId=0x" + Integer.toHexString(streamId));
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(packet);
        frame.decode(impl, byteBuffer);
        if (byteBuffer.hasRemaining()) {
            byte[] remaining = new byte[byteBuffer.remaining()];
            byteBuffer.get(remaining);
            throw new H2Exception("End of packet was expected: " + frame + ", remaining=" + HexFormatter.format(remaining));
        }
        if (log.isDebugEnabled()) {
            log.debug("decodeBuffer frame={}, data={}", frame, HexFormatter.encodeHexString(packet));
        }
        return frame;
    }

    public abstract H2Frame decode(DataInputStream is) throws H2Exception;

    public void decode(HttpSessionImpl impl, ByteBuffer buffer) throws H2Exception {
        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);
        throw new UnsupportedOperationException(getClass().getName() + ", data=" + HexFormatter.encodeHexString(data));
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final H2Frame other = (H2Frame) obj;
        if (this.controlBit != other.controlBit) {
            return false;
        }
        if (this.flags != other.flags) {
            return false;
        }
        return this.length == other.length;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 73 * hash + (this.controlBit ? 1 : 0);
        hash = 73 * hash + this.flags;
        hash = 73 * hash + this.length;
        return hash;
    }
}
