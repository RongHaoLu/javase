package com.rh.jwt.utis;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.Date;

/**
 * @Author RongHaoLu
 * @Date 2023/3/7 00:06
 * JWT工具类
 * 令牌组成
 * - 1.标头(Header)
 * - 2.有效载荷(Payload)
 * - 3.签名(Signature)
 */
public class JwtUtils {

    /**
     * 两个常量
     */
    public static final long EXPIRE = 1000*60*60*24;
    public static final String SECRET = "ukc8BDbRigUDaY6pUFfWus2jZWLPHO";

    /**
     * 生成token字符串的方法
     * @param id
     * @param nickname
     * @return
     */
    public static String getJwtToken(String id,String nickname){
        String JwtToken = Jwts.builder()
                //JWT头信息
                .setHeaderParam("typ","JWT")
                .setHeaderParam("alg","HS2256")
                //设置分类；设置过期时间 一个当前时间，一个加上设置的过期时间常量
                .setSubject("rh-user")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+EXPIRE))
                //设置token主体信息，存储用户的数据
                .claim("id",id)
                .claim("nickname",nickname)
                .signWith(SignatureAlgorithm.ES256,SECRET)
                .compact();
        return JwtToken;
    }

    /**
     * 判断token是否存在与有效
     * @param jwtToken
     * @return
     */
    public static boolean checkToken(String jwtToken){
        if (StringUtils.isEmpty(jwtToken)){
            return false;
        }
        try {
            //验证token
            Jwts.parser().setSigningKey(SECRET).parseClaimsJws(jwtToken);
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static String getMemberIdByJwtToken(MockHttpServletRequest request){
        String token = request.getHeader("token");
        if (StringUtils.isEmpty(token)){
            return "";
        }
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token);
        Claims body = claimsJws.getBody();
        return (String) body.get("id");
    }


}
