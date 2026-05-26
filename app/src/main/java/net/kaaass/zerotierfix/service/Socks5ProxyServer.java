package net.kaaass.zerotierfix.service;

import android.util.Log;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * SOCKS5 proxy server that tunnels traffic through ZeroTier.
 * This server listens for SOCKS5 connections and forwards them through the ZeroTier network.
 */
public class Socks5ProxyServer {
    private static final String TAG = "Socks5ProxyServer";
    
    private ServerSocket serverSocket;
    private ExecutorService executorService;
    private volatile boolean isRunning = false;
    private int port;
    private boolean enableAuth;
    private String username;
    private String password;
    private Socks5ConnectionHandler connectionHandler;
    
    /**
     * Interface for handling SOCKS5 connections
     */
    public interface Socks5ConnectionHandler {
        void onConnectionEstablished(Socket clientSocket, Socket targetSocket);
        void onError(Exception e);
    }
    
    public Socks5ProxyServer(int port, boolean enableAuth, String username, String password) {
        this.port = port;
        this.enableAuth = enableAuth;
        this.username = username;
        this.password = password;
        this.executorService = Executors.newCachedThreadPool();
    }
    
    /**
     * Start the SOCKS5 proxy server
     */
    public void start(Socks5ConnectionHandler handler) throws IOException {
        if (isRunning) {
            Log.w(TAG, "SOCKS5 proxy already running");
            return;
        }
        
        this.connectionHandler = handler;
        this.serverSocket = new ServerSocket();
        this.serverSocket.setReuseAddress(true);
        this.serverSocket.bind(new InetSocketAddress(port));
        this.isRunning = true;
        
        // Start accepting connections in a separate thread
        executorService.submit(this::acceptConnections);
        
        Log.i(TAG, "SOCKS5 proxy started on port " + port + 
              (enableAuth ? " with authentication" : " without authentication"));
    }
    
    /**
     * Accept incoming connections
     */
    private void acceptConnections() {
        while (isRunning && !Thread.currentThread().isInterrupted()) {
            try {
                Socket clientSocket = serverSocket.accept();
                Log.d(TAG, "Accepted connection from " + clientSocket.getRemoteSocketAddress());
                
                // Handle each connection in a separate thread
                executorService.submit(() -> handleClientConnection(clientSocket));
            } catch (SocketException e) {
                if (isRunning) {
                    Log.e(TAG, "Socket error while accepting connections", e);
                }
            } catch (IOException e) {
                if (isRunning) {
                    Log.e(TAG, "Error accepting connection", e);
                    if (connectionHandler != null) {
                        connectionHandler.onError(e);
                    }
                }
            }
        }
    }
    
    /**
     * Handle a single client connection
     */
    private void handleClientConnection(Socket clientSocket) {
        try {
            // Set socket timeout
            clientSocket.setSoTimeout(30000); // 30 seconds timeout
            
            // Perform SOCKS5 handshake
            boolean handshakeSuccessful = performHandshake(clientSocket);
            if (!handshakeSuccessful) {
                Log.e(TAG, "SOCKS5 handshake failed");
                clientSocket.close();
                return;
            }
            
            // Parse the SOCKS5 request
            Socks5Request request = parseRequest(clientSocket);
            if (request == null) {
                Log.e(TAG, "Failed to parse SOCKS5 request");
                clientSocket.close();
                return;
            }
            
            // Connect to the target host
            Socket targetSocket = new Socket();
            targetSocket.setSoTimeout(30000);
            targetSocket.connect(new InetSocketAddress(request.host, request.port), 10000);
            
            // Send success response
            sendSuccessResponse(clientSocket, request.host, request.port);
            
            // Notify handler
            if (connectionHandler != null) {
                connectionHandler.onConnectionEstablished(clientSocket, targetSocket);
            }
            
            // Start bidirectional data transfer
            startDataTransfer(clientSocket, targetSocket);
            
        } catch (IOException e) {
            Log.e(TAG, "Error handling client connection", e);
            try {
                clientSocket.close();
            } catch (IOException ex) {
                Log.e(TAG, "Error closing client socket", ex);
            }
        }
    }
    
    /**
     * Perform SOCKS5 handshake
     */
    private boolean performHandshake(Socket socket) throws IOException {
        var in = socket.getInputStream();
        var out = socket.getOutputStream();
        
        // Read version and number of authentication methods
        int version = in.read();
        if (version != 0x05) {
            Log.e(TAG, "Unsupported SOCKS version: " + version);
            return false;
        }
        
        int numMethods = in.read();
        byte[] methods = new byte[numMethods];
        in.read(methods);
        
        // Choose authentication method
        byte selectedMethod = 0xFF;
        if (enableAuth) {
            // Check if username/password authentication is supported
            for (byte method : methods) {
                if (method == 0x02) { // Username/password authentication
                    selectedMethod = 0x02;
                    break;
                }
            }
        } else {
            // Check if no authentication is supported
            for (byte method : methods) {
                if (method == 0x00) { // No authentication
                    selectedMethod = 0x00;
                    break;
                }
            }
        }
        
        if (selectedMethod == 0xFF) {
            Log.e(TAG, "No acceptable authentication method");
            out.write(new byte[]{0x05, 0xFF}); // No acceptable method
            out.flush();
            return false;
        }
        
        // Send selected method
        out.write(new byte[]{0x05, selectedMethod});
        out.flush();
        
        // Perform authentication if required
        if (selectedMethod == 0x02) {
            return performAuthentication(socket);
        }
        
        return true;
    }
    
    /**
     * Perform username/password authentication
     */
    private boolean performAuthentication(Socket socket) throws IOException {
        var in = socket.getInputStream();
        var out = socket.getOutputStream();
        
        // Read authentication request
        int version = in.read();
        if (version != 0x01) {
            Log.e(TAG, "Unsupported authentication version: " + version);
            return false;
        }
        
        int usernameLength = in.read();
        byte[] usernameBytes = new byte[usernameLength];
        in.read(usernameBytes);
        String clientUsername = new String(usernameBytes);
        
        int passwordLength = in.read();
        byte[] passwordBytes = new byte[passwordLength];
        in.read(passwordBytes);
        String clientPassword = new String(passwordBytes);
        
        // Validate credentials
        boolean authenticated = username.equals(clientUsername) && password.equals(clientPassword);
        
        // Send authentication response
        if (authenticated) {
            out.write(new byte[]{0x01, 0x00}); // Success
            out.flush();
            Log.d(TAG, "Authentication successful for user: " + clientUsername);
            return true;
        } else {
            out.write(new byte[]{0x01, 0x01}); // Failure
            out.flush();
            Log.e(TAG, "Authentication failed for user: " + clientUsername);
            return false;
        }
    }
    
    /**
     * Parse SOCKS5 request
     */
    private Socks5Request parseRequest(Socket socket) throws IOException {
        var in = socket.getInputStream();
        
        // Read request header
        int version = in.read();
        if (version != 0x05) {
            Log.e(TAG, "Invalid request version: " + version);
            return null;
        }
        
        int cmd = in.read();
        if (cmd != 0x01) { // Only CONNECT command is supported
            Log.e(TAG, "Unsupported command: " + cmd);
            return null;
        }
        
        int reserved = in.read(); // Should be 0x00
        int addressType = in.read();
        
        String host;
        int port;
        
        switch (addressType) {
            case 0x01: // IPv4 address
                byte[] ipv4 = new byte[4];
                in.read(ipv4);
                host = String.format("%d.%d.%d.%d", ipv4[0] & 0xFF, ipv4[1] & 0xFF, 
                                     ipv4[2] & 0xFF, ipv4[3] & 0xFF);
                break;
            case 0x03: // Domain name
                int domainLength = in.read();
                byte[] domainBytes = new byte[domainLength];
                in.read(domainBytes);
                host = new String(domainBytes);
                break;
            case 0x04: // IPv6 address
                byte[] ipv6 = new byte[16];
                in.read(ipv6);
                StringBuilder ipv6Builder = new StringBuilder();
                for (int i = 0; i < 16; i += 2) {
                    if (i > 0) ipv6Builder.append(":");
                    ipv6Builder.append(String.format("%02x%02x", ipv6[i] & 0xFF, ipv6[i+1] & 0xFF));
                }
                host = ipv6Builder.toString();
                break;
            default:
                Log.e(TAG, "Unsupported address type: " + addressType);
                return null;
        }
        
        port = ((in.read() & 0xFF) << 8) | (in.read() & 0xFF);
        
        Log.d(TAG, "SOCKS5 request: CONNECT " + host + ":" + port);
        return new Socks5Request(host, port);
    }
    
    /**
     * Send success response to client
     */
    private void sendSuccessResponse(Socket socket, String host, int port) throws IOException {
        var out = socket.getOutputStream();
        
        // Send success response (bind to 0.0.0.0:0)
        byte[] response = new byte[]{
            0x05, 0x00, 0x00, 0x01, // SOCKS5, success, reserved, IPv4
            0x00, 0x00, 0x00, 0x00, // 0.0.0.0
            0x00, 0x00               // port 0
        };
        out.write(response);
        out.flush();
    }
    
    /**
     * Start bidirectional data transfer between client and target
     */
    private void startDataTransfer(Socket clientSocket, Socket targetSocket) {
        ExecutorService transferExecutor = Executors.newFixedThreadPool(2);
        
        // Client -> Target
        transferExecutor.submit(() -> {
            try {
                byte[] buffer = new byte[8192];
                int bytesRead;
                var clientIn = clientSocket.getInputStream();
                var targetOut = targetSocket.getOutputStream();
                
                while ((bytesRead = clientIn.read(buffer)) != -1) {
                    targetOut.write(buffer, 0, bytesRead);
                    targetOut.flush();
                }
            } catch (IOException e) {
                Log.d(TAG, "Client to target transfer ended: " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException ignored) {}
                try {
                    targetSocket.close();
                } catch (IOException ignored) {}
            }
        });
        
        // Target -> Client
        transferExecutor.submit(() -> {
            try {
                byte[] buffer = new byte[8192];
                int bytesRead;
                var targetIn = targetSocket.getInputStream();
                var clientOut = clientSocket.getOutputStream();
                
                while ((bytesRead = targetIn.read(buffer)) != -1) {
                    clientOut.write(buffer, 0, bytesRead);
                    clientOut.flush();
                }
            } catch (IOException e) {
                Log.d(TAG, "Target to client transfer ended: " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException ignored) {}
                try {
                    targetSocket.close();
                } catch (IOException ignored) {}
                transferExecutor.shutdownNow();
            }
        });
    }
    
    /**
     * Stop the SOCKS5 proxy server
     */
    public void stop() {
        isRunning = false;
        
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            Log.e(TAG, "Error closing server socket", e);
        }
        
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        Log.i(TAG, "SOCKS5 proxy stopped");
    }
    
    public boolean isRunning() {
        return isRunning;
    }
    
    /**
     * SOCKS5 request data class
     */
    private static class Socks5Request {
        final String host;
        final int port;
        
        Socks5Request(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
}
