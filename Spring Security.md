# Spring Security

![Page View](https://gimg2.baidu.com/image_search/src=http%3A%2F%2Frealwealthbusiness.com%2Fwp-content%2Fuploads%2F2019%2F09%2F38-Converted.jpg&refer=http%3A%2F%2Frealwealthbusiness.com&app=2002&size=f9999,10000&q=a80&n=0&g=0n&fmt=auto?sec=1666768288&t=6e32b4ae7e074725d54b906790296fda)

前置知识：

1、<span style="color:red;">掌握Spring框架</span>

2、<span style="color:#833237;">掌握SpringBoot使用</span>

3、<span style="color:blue;">掌握JavaWeb技术</span>



## 简介

[官方网址](https://spring.io/projects/spring-security)

**概要**

Spring Security基于Spring框架，提供了一套Web应用安全性的完整解决方案。

关于安全方面的两个主要区域是：<strong style="color:blue;">认证</strong> 和 <strong style="color:blue;">授权</strong>（或者访问控制）。

一般来说，Web应用的安全性包括 <strong style="color:red;">用户认证 Authentication</strong> 和 <strong style="color:red;">用户授权Authorization</strong> 两部分，这也是Spring Security的核心功能。

（1）用户认证

验证某个用户是否为系统中的合法主体，也就是说用户能否访问该系统。

用户认证一般要求用户提供用户名和密码，系统通过校验用户名和密码来完成认证。

<span style="color:blue;">通俗点说，就是系统任务用户是否能登录</span>

（2）用户授权

验证用户是否有权限执行某个操作。

在一个系统中，不同用户所具有的权限是不同的。

一般来说，系统会为不同的用户分配不同的角色，而每个角色则对应一系列的权限。

<span style="color:blue;">通俗点说，就是系统判断用户是否有权限去做某些事情</span>



**同款产品对比**

`Spring Security`

- 和Spring无缝整合
- 全面的权限控制
- 专门为Web开发而设计
  - 旧版本不能脱离Web环境使用
  - 新版本对整个框架进行了分层抽取，分成了核心模块和Web模块。（单独引入核心模块就可以脱离Web环境）
- 重量级框架（依赖于很多其他组件，另外里面需要引入各种依赖）



`Shiro`

Apache旗下的轻量级权限控制框架

- 轻量级。Shiro主张的理念是把复杂的事情变简单，针对 *对性能有更高要求的互联网应用* 有更好表现
- 通用性
  - 好处：不局限于Web环境，可以脱离Web环境使用
  - 缺陷：在Web环境下一些特定的需求需要手动编写代码定制



==常见的安全管理技术栈的组合有==：

- SSM + Shiro
- Spring Boot / Spring Cloud + Spring Security



**模块划分**

![模块划分](./images/模块划分.png)



## 入门案例

第一步 创建Spring Boot工程

![创建Spring Boot工程01](./images/创建Spring Boot工程01.png)



![创建Spring Boot工程02](./images/创建Spring Boot工程02.png)



第二步 引入相关依赖

```xml
<!--需要导入web场景的启动器，否则项目在启动运行后会立即结束并退出-->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```



第三步 编写Controller进行测试

```java
package com.djn.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
```



第四步 在浏览器中访问http://localhost:8899/test/hello，画面如下

![入门案例项目启动页面访问](./images/入门案例项目启动页面访问.png)

出现这个页面说明我们引入的Spring Security已经生效了

**此时我们需要使用Spring Security默认的用户名“user”去登录**

密码在IDEA项目运行着的控制台中查看

![Spring Security的动态密码](./images/Spring Security的动态密码.png)



### 基本原理

#### 过滤器链

<strong style="color:blue;">Spring Security的本质是一个过滤器链</strong>，有很多过滤器

通过源码，重点查看三个过滤器

**FilterSecurityInterceptor**：<span style="color:green;">这是一个方法级的权限过滤器，基本位于过滤器链的最底部</span>

![FilterSecurityInterceptor](./images/FilterSecurityInterceptor.png)

`super.beforeInvocation(fi)`

- 表示在执行前查看上一个filter是否通过

`filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse())`

- 表示真正的调用后台的服务



**ExceptionTranslationFilter**：<span style="color:blue;">是一个异常过滤器，用来处理在认证授权过程中抛出的异常</span>

![ExceptionTranslationFilter](./images/ExceptionTranslationFilter.png)



**UsernamePasswordAuthenticationFilter**：<span style="color:red;">对/login的POST请求做拦截，校验表单中的用户名、密码</span>

![UsernamePasswordAuthenticationFilter](./images/UsernamePasswordAuthenticationFilter.png)



#### 过滤器加载过程

过滤器是如何进行加载的？

①使用Spring Security，首先要配置过滤器 **DelegatingFilterProxy**（在SpringBoot中，这一步被自动化配置代替，所以省略了）
