package com.abbypan.cryptoutils;


import java.security.*;
import java.util.Arrays;
import com.abbypan.cryptoutils.HexUtils;
import com.abbypan.cryptoutils.Digest;

//import java.security.spec.ECParameterSpec;
//import java.security.spec.ECPublicKeySpec;
import java.security.Security;


//import org.bouncycastle.jce.spec.ECGenParameterSpec;



public class CryptoUtils 
{
   


    public static void printAlgList(String utilName){
        System.out.println(Security.getAlgorithms(utilName));
    }
    public static void printProviderList(){
        System.out.println(Arrays.toString(Security.getProviders()));
    }





















}
