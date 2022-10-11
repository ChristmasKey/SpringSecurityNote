package com.djn.service;

import com.djn.mapper.UserMapper;
import lombok.val;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Resource
    private PasswordEncoder bCryptPwdEncoder;

    @Resource
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //查询数据库
        val user = userMapper.selectUserByName(username);
        //判断用户是否存在
        if (user == null) throw new UsernameNotFoundException("用户不存在！");
        //设置用户权限，后面会从数据库查
        List<GrantedAuthority> authorities =
                AuthorityUtils.commaSeparatedStringToAuthorityList("admin,user,ROLE_sale,ROLE_manage");
        //根据查到的用户生成Security中的User对象，并返回
        return new User(user.getUsername(), bCryptPwdEncoder.encode(user.getPassword()), authorities);
    }
}
