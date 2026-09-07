package com.example.authserver.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

/**
 * Spring Security JwtEncoder implementation backed by AWS KMS.
 * Encodes Access Tokens and ID Tokens and delegates cryptographic signing
 * to KmsRsaSigner without private keys ever entering host memory.
 */
@Slf4j
@RequiredArgsConstructor
public class KmsJwtEncoder implements JwtEncoder {

    private final KmsRsaSigner kmsRsaSigner;
    private final String keyId;

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
        try {
            JwsHeader jwsHeader = parameters.getJwsHeader();
            JwtClaimsSet claims = parameters.getClaims();

            // Build Nimbus JWSHeader with algorithm RS256, type JWT, and public key ID
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
            headerBuilder.type(JOSEObjectType.JWT);

            String activeKeyId = (jwsHeader.getKeyId() != null && !jwsHeader.getKeyId().isBlank())
                    ? jwsHeader.getKeyId()
                    : this.keyId;
            if (activeKeyId != null) {
                headerBuilder.keyID(activeKeyId);
            }

            for (Map.Entry<String, Object> entry : jwsHeader.getHeaders().entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                if ("alg".equalsIgnoreCase(key) || "kid".equalsIgnoreCase(key) || "typ".equalsIgnoreCase(key)) {
                    continue;
                }
                headerBuilder.customParam(key, val);
            }
            JWSHeader nimbusHeader = headerBuilder.build();

            // Build Nimbus JWTClaimsSet
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
            for (Map.Entry<String, Object> entry : claims.getClaims().entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                if (val instanceof Instant instant) {
                    claimsBuilder.claim(key, Date.from(instant));
                } else {
                    claimsBuilder.claim(key, val);
                }
            }
            JWTClaimsSet nimbusClaims = claimsBuilder.build();

            // Cryptographically sign inside AWS KMS boundary
            SignedJWT signedJWT = new SignedJWT(nimbusHeader, nimbusClaims);
            signedJWT.sign(kmsRsaSigner);

            String tokenValue = signedJWT.serialize();

            return new Jwt(
                    tokenValue,
                    claims.getIssuedAt(),
                    claims.getExpiresAt(),
                    nimbusHeader.toJSONObject(),
                    claims.getClaims()
            );
        } catch (Exception ex) {
            log.error("Failed to encode JWT with AWS KMS: {}", ex.getMessage(), ex);
            throw new JwtEncodingException("Strict Fail-Closed: An error occurred while attempting to encode JWT via AWS KMS: " + ex.getMessage(), ex);
        }
    }
}
