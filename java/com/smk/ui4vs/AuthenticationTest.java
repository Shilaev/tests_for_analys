package com.smk.ui4vs;

import com.smk.ui4vs.models.roles_model.*;
import com.smk.ui4vs.repositories.*;
import com.smk.ui4vs.services.DeactivatedTokensService;
import com.smk.ui4vs.services.SecurityService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.DockerImageName;

import javax.security.auth.login.AccountLockedException;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;
import static org.junit.jupiter.api.parallel.ExecutionMode.CONCURRENT;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@TestInstance(PER_CLASS)
@ExtendWith(MockitoExtension.class)
@SpringBootTest
public class AuthenticationTest {

    //region    dependencies
    private final SecurityService securityService;
    private final UsersRepository usersRepository;
    private final RolesRepository rolesRepository;
    private final AuthoritiesRepository authoritiesRepository;
    private final TokensRepository tokensRepository;
    private final MockMvc mvc;
    //endregion dependencies

    //region    entities for tests
    private User admin;
    private Authority adminAuthority;
    private Role adminRole;
    private Token adminToken;
    private Namespace adminNamespace;
    private String adminPasswordNonEncoded;

    private User user;
    private Authority userAuthority;
    private Role userRole;
    private Token userToken;
    private Namespace userNamespace;
    private String userPasswordNonEncoded;
    //endregion entities for tests

    //region    setup testcontainer
    @Container
    private static final PostgreSQLContainer<?> postgresContainer = new PostgreSQLContainer<>("postgres:16")
            .withReuse(true)
            .withInitScript("create-schemas.sql");

    @Container
    private static GenericContainer<?> redisContainer = new GenericContainer<>(DockerImageName.parse("bitnami/redis:latest"))
            .withExposedPorts(6379)
            .withEnv("REDIS_PASSWORD", "ui4vs");

    static {
        postgresContainer.start();
        redisContainer.start();
    }

    @Autowired private AuthenticationManagerBuilder authenticationManagerBuilder;
    @Autowired private MockMvc mockMvc;
    @Autowired private DeactivatedTokensService deactivatedTokensService;
    @Autowired private NamespaceRepository namespaceRepository;

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgresContainer::getJdbcUrl);
        registry.add("spring.datasource.username", postgresContainer::getUsername);
        registry.add("spring.datasource.password", postgresContainer::getPassword);

        registry.add("spring.data.redis.host", redisContainer::getHost);
        registry.add("spring.data.redis.port", () -> redisContainer.getMappedPort(6379));
        registry.add("spring.data.redis.password", () -> "ui4vs");

        System.out.println(redisContainer.getHost());
        System.out.println(redisContainer.getMappedPort(6379));
    }
    //endregion setup testcontainer

    @Autowired
    public AuthenticationTest(SecurityService securityService, UsersRepository usersRepository, RolesRepository rolesRepository, AuthoritiesRepository authoritiesRepository, TokensRepository tokensRepository, MockMvc mvc) {
        this.securityService = securityService;
        this.usersRepository = usersRepository;
        this.rolesRepository = rolesRepository;
        this.authoritiesRepository = authoritiesRepository;
        this.tokensRepository = tokensRepository;
        this.mvc = mvc;
    }

    @BeforeAll
    void beforeAll() throws AccountLockedException {
        //region    setup entities for tests

        //region    creating admin
        adminPasswordNonEncoded = "admin";

        adminAuthority = new Authority(
                "ADMIN", "administration access only"
        );
        authoritiesRepository.save(adminAuthority);

        adminNamespace = namespaceRepository.save(new Namespace("admin_namespace", null, null, null, null, null));

        adminRole = new Role(
                "admin",
                "administration authorities",

                Set.of(adminAuthority)
        );
        rolesRepository.save(adminRole);

        admin = securityService.createUserWithDefaults(
                "admin", adminPasswordNonEncoded,
                "Имя", "Фамилия", adminNamespace.getTitle(), Set.of(adminRole.getTitle())
        );

        adminToken = securityService.createTokenWithDefaults(
                admin.getUsername(),
                securityService.mapGrantedAuthoritiesToAuthority(admin.getAuthorities())
        );

        tokensRepository.save(adminToken);
        admin.setToken(adminToken);
        securityService.applyToken(admin.getUsername(), adminToken);

        assertThat(authoritiesRepository.findByTitle("ADMIN")).isPresent();
        assertThat(rolesRepository.findByTitle("admin")).isPresent();
        assertThat(usersRepository.findByUsername("admin")).isPresent();
        assertThat(tokensRepository.findByKey(adminToken.getKey())).isPresent();
        assertThat(usersRepository.findByUsername("admin").get().getToken()).isNotNull();
        //endregion creating admin

        //region    creating regular user
        userPasswordNonEncoded = "user";

        userAuthority = new Authority(
                "USER", "user access only"
        );
        authoritiesRepository.save(userAuthority);

        userNamespace = namespaceRepository.save(new Namespace("user_namespace", null, null, null, null, null));

        userRole = new Role(
                "user",
                "user authorities",
                Set.of(userAuthority)
        );
        rolesRepository.save(userRole);

        user = securityService.createUserWithDefaults(
                "user", userPasswordNonEncoded,
                "Имя", "Фамилия", userNamespace.getTitle(), Set.of(userRole.getTitle())
        );

        userToken = securityService.createTokenWithDefaults(
                user.getUsername(),
                securityService.mapGrantedAuthoritiesToAuthority(user.getAuthorities())
        );
        tokensRepository.save(userToken);
        user.setToken(userToken);
        securityService.applyToken(user.getUsername(), userToken);

        assertThat(authoritiesRepository.findByTitle("USER")).isPresent();
        assertThat(rolesRepository.findByTitle("user")).isPresent();
        assertThat(usersRepository.findByUsername("user")).isPresent();
        assertThat(tokensRepository.findByKey(userToken.getKey())).isPresent();
        assertThat(usersRepository.findByUsername("user").get().getToken()).isNotNull();


        //endregion creating regular user

        //endregion setup entities for tests
    }

    //region    loginForm check
    @Test @Execution(CONCURRENT)
    void when_user_tryingTo_login_with_correctUsernamePassword_thenReturn_isFoundStatus() throws Exception {
        mvc.perform(formLogin("/login").user(admin.getUsername()).password(adminPasswordNonEncoded))
                .andExpect(authenticated())
                .andExpect(cookie().exists("__Host-auth-token"))
                .andExpect(status().isFound());
    }

    @Test @Execution(CONCURRENT)
    public void testAuthentication() throws Exception {
        MvcResult mvcResult = mockMvc.perform(formLogin("/login")
                        .user("username", admin.getUsername())
                        .password("password", adminPasswordNonEncoded))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("admin"))
                .andReturn();

        System.out.println(mvcResult.getResponse());
    }

    @Test @Execution(CONCURRENT)
    void when_user_tryingTo_login_with_incorrectUsernamePassword_thenReturn_loginError() throws Exception {
        System.out.println();
        mvc.perform(formLogin("/login").user("notexists").password("notexists"))
                .andExpect(cookie().doesNotExist("__Host-auth-token"))
                .andExpect(status().isNotFound());
    }

    @Test @Execution(CONCURRENT) @Transactional
    void when_user_tryingTo_login_with_expiredAccount_thenThrow_accountExpiredException() {
        admin.setAccountExpired(true);
        usersRepository.save(admin);

        assertThrows(AccountExpiredException.class, () -> {
            mvc.perform(formLogin("/login")
                    .user(admin.getUsername()).password(adminPasswordNonEncoded)).andReturn();
        });

    }

    @Test @Execution(CONCURRENT) @Transactional
    void when_user_tryingTo_login_with_disableAccount_thenThrow_credentialsExpiredException() {
        admin.setCredentialsExpired(true);
        usersRepository.save(admin);
        try {
            mvc.perform(formLogin("/login")
                    .user(admin.getUsername()).password(adminPasswordNonEncoded));
        } catch (Exception e) {
            assertInstanceOf(CredentialsExpiredException.class, e);
        }
    }

    @Test @Execution(CONCURRENT) @Transactional
    void when_user_tryingTo_login_with_disableAccount_thenThrow_accountLockedException() throws Exception {
        admin.setAccountLocked(true);
        usersRepository.save(admin);

        mvc.perform(formLogin("/login")
                        .user(admin.getUsername()).password(adminPasswordNonEncoded))
                .andExpect(status().isFound());
    }

    @Test @Execution(CONCURRENT) @Transactional
    void when_user_tryingTo_login_with_disableAccount_thenThrow_accountExpiredException() {
        admin.setAccountExpired(true);
        usersRepository.save(admin);

        assertThrows(AccountExpiredException.class, () ->
                mvc.perform(formLogin("/login")
                        .user(admin.getUsername()).password(adminPasswordNonEncoded)));
    }

    @Test
    void when_getAuthoritiesFromJwt_thenOk() throws Exception {
        MvcResult mvcResult = mvc.perform(formLogin("/login")
                .user(admin.getUsername()).password(adminPasswordNonEncoded)).andReturn();


        //todo :
        Cookie first = Arrays.stream(mvcResult.getResponse().getCookies())
                .filter(cookie -> cookie.getName().equals("__Host-auth-token")).findFirst().get();


        MvcResult mvcResult1 = mvc.perform(post("jwt/get-authorities")
                .with(csrf())
                .with(user(admin))
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(first.getValue())).andExpect(status().isOk()).andReturn();

        System.out.println(mvcResult1.getResponse());

    }

    //endregion loginForm checks

    //region    authentication check
    @Test @Execution(CONCURRENT)
    void when_user_loginFormSuccess_thenReturn_isAuthenticated() throws Exception {
        mvc.perform(formLogin("/login").user(user.getUsername()).password(userPasswordNonEncoded))
                .andExpect(authenticated().withAuthentication(auth -> {
                    assertThat(auth).isInstanceOf(UsernamePasswordAuthenticationToken.class);
                    assertThat(auth.getPrincipal()).isInstanceOf(User.class);

                    User authenticatedUser = (User) auth.getPrincipal();
                    assertThat(authenticatedUser.getUsername()).isEqualTo(user.getUsername());
                    assertThat(authenticatedUser.getPassword()).isEqualTo(user.getPassword());


                    assertThat(securityService.findUserByUsername(user.getUsername()).getToken()).isNotNull();
                    assertThat(securityService.findUserByUsername(user.getUsername()).getToken().getSubject()).isEqualTo(((User) auth.getPrincipal()).getToken().getSubject());
                }));

    }

    @Test @Execution(CONCURRENT)
    void when_user_loginFormFailure_thenReturn_isUnauthenticated() throws Exception {
        mvc.perform(formLogin("/login").user("not_exists").password("not_exists"))
                .andExpect(unauthenticated());
    }
    //endregion authentication check

    //region    authorization check
    @Test @Execution(CONCURRENT)
    void when_user_with_validAuthorities_tryingTo_getProtectedPage_thenReturn_statusIsOk() throws Exception {
        mvc.perform(get("/protected-resource").with(user(admin)))
                .andExpect(authenticated())
                .andExpect(redirectedUrl(null));
    }

    @Test @Execution(CONCURRENT)
    void when_user_with_noValidAuthorities_tryingTo_getProtectedPage_thenRedirectTo_accessDeniedPage() throws Exception {
        mvc.perform(get("/protected-resource").with(user(user)))
                .andExpect(authenticated())
                .andExpect(status().isForbidden())
                .andExpect(redirectedUrl("/access-denied"));
    }
    //endregion authorization check

    //region    logout check
    @Test
    void when_logout_then_setUserTokenIsValid_False_addUserTokenTo_redisDeactivatedTokenList() throws Exception {
        mockMvc.perform(post("/logout")
                        .with(user(user)).with(csrf()))
                .andExpect(redirectedUrlPattern("/login?logout"))
                .andReturn();

        UUID tokenKey = user.getToken().getKey();

        assertThat(deactivatedTokensService.checkTokenDeactivated(tokenKey)).isTrue();
        assertThat(usersRepository.findByUsername(user.getUsername()).get().getToken().getIsActive()).isFalse();
    }

    @Test
    void when_userLoginAgain_then_removeUserToken_from_redisDeactivatedTokenList() throws Exception {
        mvc.perform(formLogin("/login").user(user.getUsername()).password(userPasswordNonEncoded))
                .andExpect(authenticated())
                .andExpect(cookie().exists("__Host-auth-token"))
                .andExpect(status().isFound());

        UUID tokenKey = user.getToken().getKey();

        assertThat(deactivatedTokensService.checkTokenDeactivated(tokenKey)).isFalse();
        assertThat(usersRepository.findByUsername(user.getUsername()).get().getToken().getIsActive()).isTrue();

    }

    @Test
    void when_doPost_then_checkCsrfToken() throws Exception {
        MvcResult mvcResult = mvc.perform(formLogin("/login").user(admin.getUsername()).password(adminPasswordNonEncoded))
                .andExpect(authenticated())
                .andExpect(status().isFound()).andReturn();

        Cookie[] cookies = mvcResult.getResponse().getCookies();
        for (Cookie cookie : cookies) {
            if ("XSRF-TOKEN".equals(cookie.getName())) {
                System.out.println(cookie.getName() + " " + cookie.getValue());
            }
        }

    }

    //endregion logout check

    //region    Security service
    @Test @Execution(CONCURRENT)
    void when_securityService_findUserByKey_then_successFound() {
        User usersByUUID = securityService.findUserByKey(user.getKey().toString());

        assertThat(usersByUUID).isNotNull();
        assertThat(usersByUUID.getUsername()).isEqualTo(user.getUsername());
    }
    //endregion Security service
}
