package com.cos.security1.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.oauth.provider.FacebookUserInfo;
import com.cos.security1.oauth.provider.GoogleUserInfo;
import com.cos.security1.oauth.provider.NaverUserInfo;
import com.cos.security1.oauth.provider.OAuth2UserInfo;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // 구글로부터 받은 userRequest 데이터에 대한 후처리 함수
    // 해당 함수가 종료될 때 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println(userRequest.getClientRegistration());
        System.out.println(userRequest.getAccessToken().getTokenValue());

        OAuth2User oauth2User = super.loadUser(userRequest);

        // 구글 로그인 버튼 클릭 -> 로그인 창 -> 로그인 완료 -> code 리턴(Oauth-Client 라이브러리) -> AccessToken 요청
        // userRequest 정보 -> loadUser 함수 호출 -> 구글로부터 회원 프로필 받아준다.
        System.out.println(super.loadUser(userRequest).getAttributes());

        // 회원가입 강제 진행
        OAuth2UserInfo oAuth2UserInfo = null;
        String platform = userRequest.getClientRegistration().getRegistrationId();

        if (platform.equals("google")) {

            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
        } else if (platform.equals("facebook")) {

            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
        } else if (platform.equals("naver")) {

            System.out.println("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo(oauth2User.getAttributes());
        } else {
            System.out.println("우리는 구글과 페이스북만 지원합니다.");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("안녕하세요");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User findUser = userRepository.findByUsername(username);
        if (findUser == null) {

            findUser = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            userRepository.save(findUser);
        }

        return new PrincipalDetails(findUser, oauth2User.getAttributes());
    }
}
