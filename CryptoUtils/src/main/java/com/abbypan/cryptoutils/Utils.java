package com.abbypan.cryptoutils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import org.apache.commons.io.HexDump;

public class Utils {
	 
	public static String hexstring(byte[] bin) {
		 return HexFormat.of().formatHex(bin);
	 }
	 
	  public static void hexdump(byte[] bin) throws ArrayIndexOutOfBoundsException, IllegalArgumentException, IOException {
			        System.out.println(hexstring(bin));
			        OutputStream stdout = System.out;
			        HexDump.dump(bin, 0, stdout, 0);
	    }
	    
	    public static byte[] intToBigEndian(long i) {
	    	ByteBuffer bb = ByteBuffer.allocate(4);
	    	bb.order(ByteOrder.BIG_ENDIAN);
	    	bb.putInt((int) i);
	    	return bb.array();
	    }
	    
	    public static byte[] stringToByteArray(String s) {
	    	return s.getBytes(StandardCharsets.UTF_8);
	    }
}
