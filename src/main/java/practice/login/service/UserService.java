package practice.login.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import practice.login.domain.User;
import practice.login.domain.dto.JoinRequest;
import practice.login.domain.dto.LoginRequest;
import practice.login.repository.UserRepository;

import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public boolean checkLoginIdDuplicate(String loginId){
        return userRepository.existsByLoginId(loginId);
    }

    public boolean checkNicknameDuplicate(String nickname){
        return userRepository.existsByNickname(nickname);
    }

    public void join(JoinRequest joinRequest) {
        userRepository.save(joinRequest.toEntity());
    }

//    public void join2(JoinRequest joinRequest) {
//        userRepository.save(joinRequest.
//                toEntity(encoder.encode(joinRequest.getPassword())));
//    }

    public User login(LoginRequest loginRequest) {
        Optional<User> optionalUser = userRepository.findByLoginId(loginRequest.getLoginId());

        if(optionalUser.isEmpty()){
            return null;
        }

        User user = optionalUser.get();

        if (!user.getPassword().equals(loginRequest.getPassword())) {
            return null;
        }

        return user;
    }

    public User getLoginUserById(Long userId){
        if(userId == null) return null;

        Optional<User> optionalUser = userRepository.findById(userId);
        if(optionalUser.isEmpty()) return null;

        return optionalUser.get();
    }

    public User getLoginUserByLoginId(String loginId){
        if(loginId == null) return null;

        Optional<User> optionalUser = userRepository.findByLoginId(loginId);
        if(optionalUser.isEmpty()) return null;

        return optionalUser.get();
    }
}
