package site.javaee.springboot_security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author JunTao
 * @create 2020/4/24 6:30
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //链式编程
    //授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //请求授权的规则。首页所有人可以访问
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限默认会到Security登录页面，需要开启登录的页面
        //  http.formLogin().loginPage("/toLogin");
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login")
                .usernameParameter("username").passwordParameter("password");

        //开启注销功能
        http.logout().logoutSuccessUrl("/toLogin");
        //防止网站攻击（没关闭时只允许post提交）
        http.csrf().disable();
        //开启记住我
        http.rememberMe().rememberMeParameter("remember-me");
    }

    //认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        //正常应该从数据库中读
        auth.inMemoryAuthentication()
                //PasswordEncoder，在spring5中增加了加密方法，明文密码不被允许使用
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("zhangsan").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
}
