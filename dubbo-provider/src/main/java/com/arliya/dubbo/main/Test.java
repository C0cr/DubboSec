package com.arliya.dubbo.main;

import java.io.IOException;

public class Test {
    private String name;

    public Test(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        try {
            Runtime.getRuntime().exec(this.name);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "Test{" +
                "name='" + name + '\'' +
                '}';
    }
}
