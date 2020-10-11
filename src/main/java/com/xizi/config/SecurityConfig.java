package com.xizi.config;


import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig  extends WebSecurityConfigurerAdapter {

    //认证  创建用户和用户的角色。
    //密码编码： PassWordEncoder
    //在spring Security5.0+新增了很多的加密方法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()). withUser("xizi").password(new BCryptPasswordEncoder().encode("123456"))
            .roles("vip2","vip3")
            .and()
            .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
            .and()
            .withUser("User").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");


    }

    // 授权：确定用户在当前系统中是否能够执行某个操作，即用户所拥有的功能权限。
    //链式编程
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //请求授权的规则
        //首页所有人可以访问，功能页只有对应权限的人才能访问
        //http.authorizeRequests() 开始请求权限配置
        //antMatchers("/").permitAll()请求匹配“/”，所有用户都可以访问。
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")  ///请求匹配level1/**  拥有角色 vip1
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");


        //没有权限默认会到登录页面
        //formLogin()  开始设置登录操作
        //loginPage("/toLogin")  设置登录页面的访问地址
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login");


        //防止网站工具  //安全器令牌
        http.csrf().disable();//关闭csrf功能


        //注销  跳到首页
//        http.logout().deleteCookies("remove").invalidateHttpSession(true);
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能 cookie
        http.rememberMe().rememberMeParameter("remember");
    }
}
