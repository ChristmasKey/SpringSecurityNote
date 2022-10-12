package com.djn.controller;

import com.djn.entity.User;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Name: TestController
 * Description: 测试控制器
 * Copyright: Copyright (c) 2022 MVWCHINA All rights Reserved
 * Company: 江苏医视教育科技发展有限公司
 *
 * @author 丁佳男
 * @version 1.0
 * @since 2022-09-26 17:59
 */
@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("/hello")
    public String add() {
        return "Hello Security";
    }

    @GetMapping("/index")
    public String index() {
        return "hello index";
    }

    @GetMapping("/update")
    @Secured({"ROLE_sale", "ROLE_manager"})
    public String update() {
        return "hello update";
    }

    @GetMapping("/confirm")
    // @PreAuthorize("hasRole('ROLE_sale')")
    @PreAuthorize("hasAnyAuthority('admin')")
    public String confirm() {
        return "hello confirm";
    }

    @GetMapping("/postConfirm")
    @PostAuthorize("hasAuthority('admins')")
    public String postConfirm() {
        System.out.println("postConfirm...");
        return "hello postConfirm";
    }

    @GetMapping("/getAll")
    @PreAuthorize("hasRole('ROLE_manage')")
    @PostFilter("filterObject.username != 'admin1'")
    public List<User> getAllUser() {
        List<User> users = new ArrayList<>();
        users.add(User.builder().id(1).username("admin1").password("admin1@123").build());
        users.add(User.builder().id(2).username("admin2").password("admin2@123").build());
        users.add(User.builder().id(3).username("admin3").password("admin3@123").build());
        return users;
    }

    @PostMapping("/testPreFilter")
    @PreAuthorize("hasRole('ROLE_sale')")
    @PreFilter(value = "filterObject.id % 2 == 0")
    public List<User> getTestPreFilter(@RequestBody List<User> list) {
        list.forEach(it -> {
            System.out.println(it.getId() + "\t" + it.getUsername());
        });
        return list;
    }
}
