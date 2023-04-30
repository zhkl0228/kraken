package org.krakenapps.pcap.decoder.http.h2;

import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.ZipUtil;
import junit.framework.TestCase;

public class DeflateTest extends TestCase {

    public void testDeflate() {
        byte[] data = HexUtil.decodeHex("789c5c913d0e02211046b7f2046ea2a5bd0503c3cf5e43137b18862d4d5cbd80a7b65497b170ea97c7e383e7611867be9f1ff3cccbfdc4cbf571235e2ef6386ef6afedce6782ca100d9a5cc04fc9d054d0a52fb0e0d11a0739446f5b492654ef3bc89094c11d146cca98566021b47f03a5c18114406924055cfbc59d6ac4de7014d45159e2c0ff4680757969d5ab860ce4e65543066676aa613a20d471db41ab59812006e906750009d5ad648721f51f41e29f675647d56ec4a806220dc35b");
        byte[] deflated = ZipUtil.unZlib(data);
        assertNotNull(deflated);
    }

}
