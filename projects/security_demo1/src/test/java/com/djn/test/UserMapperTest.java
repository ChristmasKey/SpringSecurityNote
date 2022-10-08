package com.djn.test;

import com.djn.entity.User;
import com.djn.mapper.UserMapper;
import org.junit.jupiter.api.Test;

import javax.annotation.Resource;

public class UserMapperTest {

    @Resource
    UserMapper userMapper;

    @Test
    public void testUserMapper() {
        User stone = userMapper.selectUserByName("SpringStone");
        System.out.println(stone);
    }
}
