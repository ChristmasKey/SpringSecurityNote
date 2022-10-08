package com.djn.service;

import com.djn.entity.User;
import com.djn.mapper.UserMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class UserService {

    @Resource
    private UserMapper userMapper;

    public User getUserByName(String username) {
        return userMapper.selectUserByName(username);
    }
}
