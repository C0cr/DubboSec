package com.arliya.dubbo.main;

import org.omg.SendingContext.RunTime;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class Test implements Serializable {
    private String name;

    public Test(String name) {
        this.name = name;
    }

    public static Object getObject() {

        Object o = new Test("calc");
        return o;
    }

}