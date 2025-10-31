package com.abbypan.cryptoutils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public class Hex {
    
    /**
     * Converts a hex string to byte array
     * @param s hex string to convert
     * @return byte array representation
     */
    public static byte[] hexstringToBytes(String s) {
        return HexFormat.of().parseHex(s);
    }

    /**
     * Converts a byte array to hex string
     * @param bin byte array to convert
     * @return hex string representation
     */
    public static String bytesToHexstring(byte[] bin) {
        return HexFormat.of().formatHex(bin);
    }

    /**
     * Prints a hex dump of the given byte array with a label
     * @param s label for the hex dump
     * @param bin byte array to dump
     * @throws IOException if an I/O error occurs
     */
    public static void hexdump(String s, byte[] bin) throws IOException {
        System.out.println("\n" + s + "\n" + bytesToHexstring(bin) + "\n");
        //  OutputStream stdout = System.out;
        //  HexDump.dump(bin, 0, stdout, 0);
    }
    
    /**
     * Converts a string to byte array using UTF-8 encoding
     * @param s the string to convert
     * @return byte array representation of the string
     */
    public static byte[] stringToBytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}