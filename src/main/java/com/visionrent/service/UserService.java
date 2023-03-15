package com.visionrent.service;

import com.visionrent.domain.User;
import com.visionrent.exception.ResourceNotFoundException;
import com.visionrent.exception.message.ErrorMessage;
import com.visionrent.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private UserRepository userRepository;


    public User getUserByEmail(String email){
        return userRepository
                .findByEmail(email)
                .orElseThrow(()-> new ResourceNotFoundException(
                        String.format(ErrorMessage.USER_NOT_FOUND_MESSAGE,email)));
    }



}
