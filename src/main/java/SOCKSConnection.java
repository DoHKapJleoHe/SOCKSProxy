import org.xbill.DNS.Address;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

public class SOCKSConnection
{
    private static final int BUFFER_LENGTH = 4096;

    private Selector selector;
    private SelectionKey clientKey;
    private SelectionKey serverKey;

    private SocketChannel clientSocket;
    private SocketChannel serverSocket;
    private States state;

    private ByteBuffer clientReadBuffer;
    private ByteBuffer serverReadBuffer;
    private ByteBuffer clientWriteBuffer;
    private ByteBuffer serverWriteBuffer;

    // SOCKS codes
    private final byte SOCKS_VER_5 = (byte)0x05;
    private final byte AUTH_METHOD_NONE = (byte)0x00;
    private final byte AUTH_METHOD_ERR = (byte)0xFF;
    private final byte TCP_STREAM = (byte)0x01;
    private final byte CONNECTION_TYPE_NOT_SUPPORTED = (byte)0x07;
    private final byte IPv4_TYPE = (byte)0x01;
    private final byte REQUEST_GRANTED = (byte)0x00;
    private final byte CONNECTION_ERROR = (byte)0x01;
    private final byte DOMAIN_TYPE = (byte)0x03;
    private final byte ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

    public SOCKSConnection(Selector selector)
    {
        this.selector = selector;
        this.state = States.GREETING;
    }

    public void handleClient(SocketChannel client) throws IOException {
        this.clientSocket = client;
        this.clientSocket.configureBlocking(false);

        clientKey = this.clientSocket.register(selector, SelectionKey.OP_READ);
        clientKey.attach(this);
    }

    public void handle(SelectionKey key)
    {
        SelectableChannel channel = key.channel();

        try
        {
            if(channel == clientSocket)
            {
                if(key.isReadable())
                {
                    switch (state)
                    {
                        case GREETING:
                            greetClient();
                            break;
                        case CONNECTING:
                            connectToServer();
                            break;
                        case RESOLVING:
                            readFromClient();
                            if (clientKey.isValid() && serverKey.isValid())
                            {
                                clientKey.interestOpsAnd(~SelectionKey.OP_READ & clientSocket.validOps());
                                serverKey.interestOpsOr(SelectionKey.OP_WRITE);
                            }
                            break;
                    }
                }
                else if (key.isWritable())
                {
                    writeToClient();
                    switch (state)
                    {
                        case GREETING:
                            System.out.println("Greeting answered");
                            state = States.CONNECTING;
                            clientKey.interestOps(SelectionKey.OP_READ);
                            break;
                        case CONNECTING:
                            state = States.RESOLVING;
                            clientKey.interestOps(SelectionKey.OP_READ);
                            break;
                        case RESOLVING:
                            clientKey.interestOpsAnd(~SelectionKey.OP_WRITE & clientSocket.validOps());
                            serverKey.interestOpsOr(SelectionKey.OP_READ);
                            break;
                    }
                }
            }
            else if (channel == serverSocket)
            {
                if (key.isReadable())
                {
                    readFromServer();
                    if (clientKey.isValid() && serverKey.isValid()) {
                        serverKey.interestOpsAnd(~SelectionKey.OP_READ & serverSocket.validOps());
                        clientKey.interestOpsOr(SelectionKey.OP_WRITE);
                    }
                }
                else if (key.isWritable())
                {
                    writeToServer();
                    if (clientKey.isValid() && serverKey.isValid())
                    {
                        serverKey.interestOpsAnd(~SelectionKey.OP_WRITE & serverSocket.validOps());
                        clientKey.interestOpsOr(SelectionKey.OP_READ);
                    }
                }
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    private void writeToClient() throws IOException {
        try
        {
            clientSocket.write(clientWriteBuffer);
        }
        catch (IOException ex)
        {
            state = States.FAIL;
            clientSocket.close();
            clientKey.cancel();
        }
    }

    private void writeToServer() throws IOException
    {
        if(serverWriteBuffer != null && serverSocket != null)
        {
            serverSocket.write(serverWriteBuffer);
        }
        else
        {
            if(serverSocket == null)
            {
                System.out.println("Error: server socket is null");
            }
            else if(serverWriteBuffer == null)
            {
                System.out.println("Error: serverWriteBuffer is null");
            }
        }
    }

    private void readFromServer() throws IOException
    {
        serverReadBuffer = ByteBuffer.allocate(BUFFER_LENGTH);
        try
        {
            int length = serverSocket.read(serverReadBuffer);
            if (length == -1)
            {
                serverSocket.close();
                serverKey.cancel();
            }
            else
            {
                byte[] write = new byte[length];
                System.arraycopy(serverReadBuffer.array(), 0, write, 0, length);
                clientWriteBuffer = ByteBuffer.wrap(write);
            }
        }
        catch (IOException ex)
        {
            state = States.FAIL;
            serverSocket.close();
            serverKey.cancel();
        }
    }

    private void readFromClient() throws IOException
    {
        // reallocating client buffer
        clientReadBuffer = ByteBuffer.allocate(BUFFER_LENGTH);

        try
        {
            int length = clientSocket.read(clientReadBuffer);
            if(length == -1)
            {
                clientSocket.close();
                clientKey.cancel();
            }
            else
            {
                byte[] toWrite = new byte[length];
                System.arraycopy(clientReadBuffer.array(), 0, toWrite, 0, length);
                serverWriteBuffer = ByteBuffer.wrap(toWrite);
            }
        }
        catch (IOException e)
        {
            state = States.FAIL;
            clientSocket.close();
            clientKey.cancel();
        }
    }

    private void connectToServer() throws IOException {
        // Reallocating client buffer
        clientReadBuffer = ByteBuffer.allocate(BUFFER_LENGTH);

        int size = clientSocket.read(clientReadBuffer);
        if(size == -1)
            state = States.FAIL;

        byte[] msg = clientReadBuffer.array();

        /*
                        FirstPacketToServer
                    |-----|-----|-----|---------|-----------|
                    | VER | CMD | RSV | DSTADDR |  DSTPORT  |
                    |-----|-----|-----|---------|-----------|
        byte_count  |  1  |  1  |  1  |   VAR   |     2     |
                    |-----|-----|-----|---------|-----------|

            VER - SOCKS version number
            CMD - Command code :
                                * 0x01 = establish a TCP/IP stream connection
                                * 0x02 = establish a TCP/IP port binding
                                * 0x03 = associate a UDP port
            DSTPORT - port number in a network byte order
            RSV - reserved, must be 0x00
            DSTADDR - destination address :
                      |------|------|
                      | TYPE | ADDR |
                      |------|------|
           byte_count |   1  |  1   |
                      |------|------|
            Type - type of the address. One of:
                                                * 0x01: IPv4 address
                                                * 0x03: Domain name
                                                * 0x04: IPv6 address
            ADDR - the address data that follows. Depending on type :
                                                * 4 bytes for IPv4 address
                                                * 1 byte of name length followed by 1–255 bytes for the domain name
                                                * 16 bytes for IPv6 address
        */

        byte[] answer = new byte[size];
        System.arraycopy(msg, 0, answer, 0, size);

        if(msg[0] != SOCKS_VER_5 || msg[1] != TCP_STREAM)
        {
            state = States.FAIL;
            answer[1] = CONNECTION_TYPE_NOT_SUPPORTED;
        }
        else
        {
            if(msg[3] == IPv4_TYPE)
            {
                byte[] ip = new byte[4];
                System.arraycopy(msg, 4, ip, 0, 4);
                int port = ((msg[8] & 0xFF) << 8) | (msg[9] & 0xFF); // ??

                // connecting to server
                try
                {
                    serverSocket = SocketChannel.open(new InetSocketAddress(InetAddress.getByAddress(ip), port));
                    serverSocket.configureBlocking(false);
                    serverKey = serverSocket.register(selector, SelectionKey.OP_READ, this);

                    answer[1] = REQUEST_GRANTED;
                }
                catch (IOException e)
                {
                    state = States.FAIL;
                    answer[1] = CONNECTION_ERROR;
                    e.printStackTrace();
                }
            }
            else if(msg[3] == DOMAIN_TYPE)
            {
                // Get domain name length in bytes
                int addrlen = msg[4];

                // Get domain name from message
                byte[] name = new byte[addrlen];
                System.arraycopy(msg, 5, name, 0, addrlen);

                try {
                    // Get address and port
                    InetAddress address = Address.getByName(new String(name));
                    byte[] ip = address.getAddress();
                    int port = ((msg[5+addrlen] & 0xff) << 8) | (msg[6+addrlen] & 0xff);

                    // Open server connection
                    serverSocket = SocketChannel.open(new InetSocketAddress(InetAddress.getByAddress(ip), port));
                    serverSocket.configureBlocking(false);
                    serverKey = serverSocket.register(selector, SelectionKey.OP_READ, this);

                    System.out.println("Connected to server " + new String(name) + ":" + port);
                    System.out.println(address.toString() + ":" + port);

                    answer[1] = REQUEST_GRANTED;
                }
                catch (IOException ex)
                {
                    ex.printStackTrace();
                    state = States.FAIL;
                    answer[1] = CONNECTION_ERROR;
                }

            }
            else
            {
                state = States.FAIL;
                answer[1] = ADDRESS_TYPE_NOT_SUPPORTED;
            }
        }

        if (state == States.FAIL)
        {
            System.out.println("Failed to connect");
        }

        clientWriteBuffer = ByteBuffer.wrap(answer);
        clientKey.interestOps(SelectionKey.OP_WRITE);
    }

    private void greetClient() throws IOException
    {
        clientReadBuffer = ByteBuffer.allocate(BUFFER_LENGTH);

        int size = clientSocket.read(clientReadBuffer);
        if(size == -1)
            state = States.FAIL;

        /*             Client greeting
                    |-----|--------|------|
                    | VER | NAUGHT | AUTH |
                    |-----|--------|------|
        byte_count  |  1  |   1    | var  |
                    |-----|--------|------|

            VER = SOCKS version number
            NAUTH = Number of authentication methods supported
            AUTH = Authentication methods, 1 byte per method supported(var, naught, auth1, auth2, auth3, ...)
        */
        byte[] msg = clientReadBuffer.array();

        /*           Server answer
                    |-----|--------|
                    | VER | CAUGHT |
                    |-----|--------|
        byte_count  |  1  |   1    |
                    |-----|--------|

            VER = SOCKS version
            CAUGHT = chosen authentication method
        */

        byte[] answer = new byte[2];
        answer[0] = SOCKS_VER_5;
        answer[1] = AUTH_METHOD_ERR;

        // checking clients SOCKS version
        if(clientReadBuffer.get(0) == 5)
        {
            for(int i = 2; i < msg[1] + 2; i++)
            {
                if(msg[i] == AUTH_METHOD_NONE)
                {
                    answer[1] = AUTH_METHOD_NONE;
                    break;
                }
            }
        }

        // checking answer[1]
        if(answer[1] == AUTH_METHOD_ERR)
        {
            state = States.FAIL;
        }

        System.out.println("Authentication method is " + answer[1]);

        // Making client socket as ready for writing
        clientKey.interestOps(SelectionKey.OP_WRITE);
    }

    private enum States
    {
        GREETING,
        CONNECTING,
        RESOLVING,
        FAIL

    }
}
