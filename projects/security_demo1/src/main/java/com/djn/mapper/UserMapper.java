package com.djn.mapper;

import com.djn.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {

    User getUserByName(String username);
}
