package com.abbypan.cryptoutils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUtils {
    
    /**
     * Reads all bytes from a file (slurp operation)
     * @param filename the path to the file to read
     * @return the file contents as a byte array
     * @throws IOException if the file cannot be read
     */
    public static byte[] slurp(String filename) throws IOException {
        Path path = Paths.get(filename);
        return Files.readAllBytes(path);
    }
    
    /**
     * Reads all bytes from a file (slurp operation) - legacy method name
     * @param filename the path to the file to read
     * @return the file contents as a byte array
     * @throws Exception if the file cannot be read
     */
    public static byte[] Slurp(String filename) throws Exception {
        try {
            return slurp(filename);
        } catch (IOException e) {
            throw new Exception("Failed to read file: " + filename, e);
        }
    }
    
    /**
     * Writes bytes to a file
     * @param filename the path to the file to write
     * @param data the data to write
     * @throws IOException if the file cannot be written
     */
    public static void writeBytes(String filename, byte[] data) throws IOException {
        Path path = Paths.get(filename);
        Files.write(path, data);
    }
    
    /**
     * Writes a string to a file using UTF-8 encoding
     * @param filename the path to the file to write
     * @param content the string content to write
     * @throws IOException if the file cannot be written
     */
    public static void writeString(String filename, String content) throws IOException {
        writeBytes(filename, content.getBytes());
    }
    
    /**
     * Reads a file as a string using UTF-8 encoding
     * @param filename the path to the file to read
     * @return the file contents as a string
     * @throws IOException if the file cannot be read
     */
    public static String readString(String filename) throws IOException {
        byte[] bytes = slurp(filename);
        return new String(bytes);
    }
    
    /**
     * Checks if a file exists
     * @param filename the path to the file to check
     * @return true if the file exists, false otherwise
     */
    public static boolean exists(String filename) {
        Path path = Paths.get(filename);
        return Files.exists(path);
    }
    
    /**
     * Gets the size of a file in bytes
     * @param filename the path to the file
     * @return the file size in bytes
     * @throws IOException if the file cannot be accessed
     */
    public static long getFileSize(String filename) throws IOException {
        Path path = Paths.get(filename);
        return Files.size(path);
    }
}
