package com.djn.mapper;

import com.djn.entity.CsrfUser;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CsrfUserMapper {

    CsrfUser selectUserByName(String username);
}
