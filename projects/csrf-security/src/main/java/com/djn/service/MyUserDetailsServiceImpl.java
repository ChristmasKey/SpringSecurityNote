package com.djn.service;

import com.djn.mapper.CsrfUserMapper;
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

@Service("myUserDetailsService")
public class MyUserDetailsServiceImpl implements UserDetailsService {

    @Resource
    private PasswordEncoder bCryptPwdEncoder;

    @Resource
    private CsrfUserMapper csrfUserMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        val user = csrfUserMapper.selectUserByName(username);
        if (user == null) throw new UsernameNotFoundException("用户不存在！");
        List<GrantedAuthority> authorities =
                AuthorityUtils.commaSeparatedStringToAuthorityList("admin");
        return new User(user.getUsername(), bCryptPwdEncoder.encode(user.getPassword()), authorities);
    }
}
