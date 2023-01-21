import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;

public class ProxyServer implements Runnable
{
    private final int port;
    private ServerSocketChannel proxySocket;
    private Selector selector;

    public ProxyServer(int proxyPort)
    {
        this.port = proxyPort;
    }

    @Override
    public void run()
    {
        try
        {
            selector = Selector.open();

            // Opening server chanel and adding it to selector
            proxySocket = ServerSocketChannel.open();
            proxySocket.bind(new InetSocketAddress(InetAddress.getByName("localhost"), port));
            proxySocket.configureBlocking(false);
            proxySocket.register(selector, SelectionKey.OP_ACCEPT);

            while (true)
            {
                selector.select();
                Set<SelectionKey> selectedKeys = selector.selectedKeys();
                Iterator<SelectionKey> iterator = selectedKeys.iterator();

                while (iterator.hasNext())
                {
                    SelectionKey key = iterator.next();

                    if(key.isAcceptable())
                    {
                        SocketChannel client = proxySocket.accept();

                        if(client != null)
                        {
                            SOCKSConnection connection = new SOCKSConnection(selector);
                            connection.handleClient(client);
                        }

                    }
                    else
                    {
                        ((SOCKSConnection)key.attachment()).handle(key);
                    }
                }
            }

        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }
}
