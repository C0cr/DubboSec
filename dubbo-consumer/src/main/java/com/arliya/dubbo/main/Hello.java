package com.arliya.dubbo.main;

import com.arliya.dubbo.api.Person;
import org.apache.xbean.spring.context.ClassPathXmlApplicationContext;

public class Hello {
    public static void main(String[] args) {
        //        ###############  正经的远程方法调用
        ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext("applicationContext.xml");
        context.start();
        Person person = (Person) context.getBean("person");
        String armandhe = person.sayHello("armandhe");
        System.out.println(armandhe);

        String name = int.class.getName();
        System.out.println(name);
    }
}
