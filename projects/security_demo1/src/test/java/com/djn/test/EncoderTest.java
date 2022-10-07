package com.djn.test;

import lombok.val;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class EncoderTest {

    @Test
    public void test01() {
        //创建密码解析器
        val encoder = new BCryptPasswordEncoder();
        //对密码进行加密
        String stone = encoder.encode("stone");
        //打印密码密文
        System.out.println("密文：" + stone);
        //判断明文密码与密文密码是否匹配
        boolean matchResult = encoder.matches("stone", stone);
        //打印匹配结果
        System.out.println("匹配结果：" + matchResult);
    }
}
