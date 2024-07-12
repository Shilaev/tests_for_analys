package com.smk.ui4vs;

import com.nimbusds.jose.JOSEException;
import com.smk.ui4vs.models.roles_model.Authority;
import com.smk.ui4vs.models.roles_model.Token;
import com.smk.ui4vs.repositories.TokensRepository;
import com.smk.ui4vs.repositories.UsersRepository;
import com.smk.ui4vs.services.DeactivatedTokensService;
import com.smk.ui4vs.services.SecurityService;
import com.smk.ui4vs.utils.jwt_marshaller.TokenJwtDeserializer;
import com.smk.ui4vs.utils.jwt_marshaller.TokenJwtSerializer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class JwtSerializerDeserializerTest {

    private final TokenJwtSerializer tokenJwtSerializer;
    private final TokenJwtDeserializer tokenJwtDeserializer;
    private final TokensRepository tokensRepository;
    private final DeactivatedTokensService deactivatedTokensService;
    private final UsersRepository usersRepository;
    @Autowired private SecurityService securityService;

    @Autowired JwtSerializerDeserializerTest(TokenJwtSerializer tokenJwtSerializer, TokenJwtDeserializer tokenJwtDeserializer, TokensRepository tokensRepository, DeactivatedTokensService deactivatedTokensService, UsersRepository usersRepository) {
        this.tokenJwtSerializer = tokenJwtSerializer;
        this.tokenJwtDeserializer = tokenJwtDeserializer;
        this.tokensRepository = tokensRepository;
        this.deactivatedTokensService = deactivatedTokensService;
        this.usersRepository = usersRepository;
    }

    @Test @Tag("JWT")
    void check_that_after_serialize_deserialize_data_was_not_distortion() throws JOSEException, ParseException {
        // create for Token
        Authority authority = securityService.createAuthority("ADMIN_ROLE", "describtion");
        Token token = securityService.createTokenDTO(
                UUID.randomUUID(),
                "username",
                Set.of(authority),
                Instant.now(),
                Instant.now().plus(Duration.ofDays(2)),
                true);

        Token tokenForSerialization = tokensRepository.save(token);

        // serialize
        String serializedToken = tokenJwtSerializer.serialize(tokenForSerialization);
        System.out.println(serializedToken);

        // deserialize
        Token deserializedToken = tokenJwtDeserializer.deserialize(serializedToken);
        System.out.println("key: " + deserializedToken.getKey() + "\n" + "subject: " + deserializedToken.getSubject() + "\n" + "authorities: " + deserializedToken.getAuthorities() + "\n" + "createdDate: " + deserializedToken.getCreatedDate() + "\n" + "expiresDate: " + deserializedToken.getExpiresDate() + "\n" + "isActive: " + deserializedToken.getIsActive());

        // check equals
        assertThat(deserializedToken.getSubject()).isEqualTo(token.getSubject());
        assertThat(deserializedToken.getAuthorities()).hasSameElementsAs(token.getAuthorities());
        assertThat(deserializedToken.getCreatedDate().truncatedTo(ChronoUnit.SECONDS)).isEqualTo(token.getCreatedDate().truncatedTo(ChronoUnit.SECONDS));
        assertThat(deserializedToken.getExpiresDate().truncatedTo(ChronoUnit.SECONDS)).isEqualTo(token.getExpiresDate().truncatedTo(ChronoUnit.SECONDS));
    }


}
