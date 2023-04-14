package edu.baylor.cs.csi5321.spdy.frames;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;

/**
 *
 * @author Lukas Camra
 */
public class SpdyFrameSynReply extends SpdyFrameStream {

    private SpdyNameValueBlock nameValueBlock;

    public SpdyNameValueBlock getNameValueBlock() {
        return nameValueBlock;
    }

    public void setNameValueBlock(SpdyNameValueBlock nameValueBlock) {
        this.nameValueBlock = nameValueBlock;
    }

    public SpdyFrameSynReply(SpdyNameValueBlock nameValueBlock, int streamId, boolean controlBit, byte flags, int length) throws SpdyException {
        super(streamId, controlBit, flags, length);
        this.nameValueBlock = nameValueBlock;
    }

    public SpdyFrameSynReply(boolean controlBit, byte flags, int length) throws SpdyException {
        super(controlBit, flags, length);
    }

    @Override
    public SpdyControlFrameType getType() {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public byte[] encode() throws SpdyException {
        
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            bout.write(nameValueBlock.encode());
            byte[] body = bout.toByteArray();
            setLength(body.length + 4);  //+4 for streamId
            byte[] header = super.encode();
            return SpdyUtil.concatArrays(header, body);
            
        } catch (IOException ex) {
            throw new SpdyException(ex);
        }
    }

    @Override
    public H2Frame decode(DataInputStream is) throws SpdyException {
        try {
            SpdyFrameSynReply f = (SpdyFrameSynReply) super.decode(is);
            byte[] pairs = new byte[f.getLength() - HEADER_LENGTH];
            is.readFully(pairs);
            f.setNameValueBlock(SpdyNameValueBlock.decode(pairs));
            return f;
        } catch (IOException ex) {
            throw new SpdyException(ex);
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
        final SpdyFrameSynReply other = (SpdyFrameSynReply) obj;
        return this.nameValueBlock.equals(other.nameValueBlock);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 41 * hash + this.nameValueBlock.hashCode();
        return hash;
    }
    
    
}
