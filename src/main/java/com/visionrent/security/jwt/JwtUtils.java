package com.visionrent.security.jwt;

import com.visionrent.exception.message.ErrorMessage;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;


@Component
public class JwtUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${visionrent.app.jwtSecret}")
    public long jwtExpirationMs;

    @Value("${visionrent.app.jwtExpirationMs}")
    public String jwtSecret;


    public String generateJwtToken(UserDetails userDetails){
        return Jwts.builder().setSubject(userDetails.getUsername())
                            .setIssuedAt(new Date())
                            .setExpiration(new Date(new Date().getTime()+jwtExpirationMs))
                            .signWith(SignatureAlgorithm.ES512,jwtSecret)
                            .compact();
    }

    public String getEmailFromToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret)
                            .parseClaimsJws(token)
                            .getBody()
                            .getSubject();
    }

    /**
     *   Parses the specified compact serialized JWS string based
     *   on the builder's current configuration state and
     *  returns the resulting Claims JWS instance.
     */
    public boolean validateJwtToken(String token){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
            //TODO please check the difference between | and ||
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException
                |SignatureException | IllegalArgumentException e){
            LOGGER.error(ErrorMessage.JWT_TOKEN_MESSAGE,e.getMessage());
        }
        return false;
    }





}
