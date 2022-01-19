package com.abbypan.cryptoutils;

import java.security.Security;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.io.*;
import java.nio.charset.StandardCharsets;


public class Digest {

	public static byte[] digest( String hashName,  byte[] s) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(hashName);
    byte[] hash = digest.digest(s);
    return hash;
	}

}
