package com.platform.auth.service;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuditService;
import com.platform.auth.common.AuthContext;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.config.AppProps;
import com.platform.auth.security.CryptoBox;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

@Service
public class SamlService {
    private static final String NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String NS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";

    private final Db db;
    private final AppProps props;
    private final CryptoBox crypto;
    private final IdentityService identities;
    private final SessionService sessions;
    private final AuditService audit;

    public SamlService(Db db, AppProps props, CryptoBox crypto, IdentityService identities,
                       SessionService sessions, AuditService audit) {
        this.db = db;
        this.props = props;
        this.crypto = crypto;
        this.identities = identities;
        this.sessions = sessions;
        this.audit = audit;
    }

    public synchronized Map<String, Object> idpConfig() {
        List<Map<String, Object>> rows = db.list("SELECT * FROM saml_idp_configs WHERE tenant_id = :tenant",
                Db.params("tenant", IdentityService.DEFAULT_TENANT));
        if (!rows.isEmpty()) {
            return rows.getFirst();
        }
        try {
            KeyPair pair = generateKeyPair();
            String certificate = selfSignedCertificate(pair);
            String entityId = props.getBaseUrl() + "/saml";
            Map<String, Object> params = Db.params(
                    "tenant", IdentityService.DEFAULT_TENANT, "entity", entityId,
                    "name", props.getWebauthnRpName(),
                    "sso", props.getBaseUrl() + "/saml/sso",
                    "slo", props.getBaseUrl() + "/saml/slo",
                    "cert", certificate,
                    "key", crypto.encrypt(pemPrivateKey(pair)));
            db.update("""
                    INSERT INTO saml_idp_configs
                    (tenant_id, enabled, entity_id, idp_name, sso_url, slo_url, certificate_pem, private_key_encrypted)
                    VALUES (:tenant, TRUE, :entity, :name, :sso, :slo, :cert, :key)
                    """, params);
            return db.one("SELECT * FROM saml_idp_configs WHERE tenant_id = :tenant",
                    Db.params("tenant", IdentityService.DEFAULT_TENANT));
        } catch (Exception e) {
            throw ApiException.internal("初始化 SAML IdP 失败: " + e.getMessage());
        }
    }

    public Map<String, Object> rotateCertificate() {
        Map<String, Object> config = idpConfig();
        try {
            KeyPair pair = generateKeyPair();
            String certificate = selfSignedCertificate(pair);
            db.update("""
                    UPDATE saml_idp_configs SET certificate_pem = :cert, private_key_encrypted = :key,
                    metadata_xml = NULL, updated_at = now() WHERE tenant_id = :tenant
                    """, Db.params("cert", certificate, "key", crypto.encrypt(pemPrivateKey(pair)),
                    "tenant", config.get("tenant_id")));
            return idpConfig();
        } catch (Exception e) {
            throw ApiException.internal("轮换证书失败");
        }
    }

    public String metadata() {
        Map<String, Object> config = idpConfig();
        String entityId = xml(String.valueOf(config.get("entity_id")));
        String sso = xml(String.valueOf(config.get("sso_url")));
        String slo = xml(String.valueOf(config.get("slo_url")));
        String certificate = String.valueOf(config.get("certificate_pem"))
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
                  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:KeyDescriptor use="signing">
                      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
                      </ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>
                    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                """.formatted(entityId, certificate, sso, sso, slo);
    }

    public String sso(Map<String, String> params, AuthContext ctx) {
        String requestXml = inflate(params.get("SAMLRequest"));
        Document request = parse(requestXml);
        Element authnRequest = documentElement(request);
        String requestId = authnRequest.getAttribute("ID");
        String acs = null;
        String issuer = null;
        NodeList assertions = request.getElementsByTagNameNS(NS_PROTOCOL, "NameIDPolicy");
        if (assertions.getLength() > 0) {
            requestId = requestId == null ? "" : requestId;
        }
        NodeList issuerNodes = request.getElementsByTagNameNS(NS_ASSERTION, "Issuer");
        if (issuerNodes.getLength() > 0) {
            issuer = issuerNodes.item(0).getTextContent();
        }
        NodeList acsNodes = request.getElementsByTagNameNS(NS_PROTOCOL, "AssertionConsumerServiceURL");
        if (acsNodes.getLength() > 0) {
            acs = acsNodes.item(0).getTextContent();
        }
        if (acs == null) {
            Map<String, Object> sp = db.list("""
                    SELECT * FROM saml_sp_configs WHERE entity_id = :entity AND status = 'active'
                    """, Db.params("entity", issuer)).stream().findFirst()
                    .orElseThrow(() -> ApiException.badRequest("未注册的 SAML SP"));
            acs = String.valueOf(sp.get("acs_url"));
        } else {
            String finalAcs = acs;
            boolean registered = db.list("SELECT id FROM saml_sp_configs WHERE acs_url = :acs AND status = 'active'",
                    Db.params("acs", finalAcs)).size() > 0;
            if (!registered) {
                throw ApiException.badRequest("ACS 地址未注册");
            }
        }
        String audience = issuer == null ? "" : issuer;
        String assertionId = "_" + UUID.randomUUID();
        String responseId = "_" + UUID.randomUUID();
        Instant now = Instant.now();
        Instant notAfter = now.plusSeconds(300);
        Map<String, Object> identity = identities.get(ctx.identityId());
        String responseXml = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s">
                  <saml:Issuer>%s</saml:Issuer>
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  <saml:Assertion ID="%s" Version="2.0" IssueInstant="%s">
                    <saml:Issuer>%s</saml:Issuer>
                    <saml:Subject>
                      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">%s</saml:NameID>
                      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                        <saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s" InResponseTo="%s"/>
                      </saml:SubjectConfirmation>
                    </saml:Subject>
                    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
                      <saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
                    </saml:Conditions>
                    <saml:AuthnStatement AuthnInstant="%s" SessionIndex="%s">
                      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
                    </saml:AuthnStatement>
                    <saml:AttributeStatement>
                      <saml:Attribute Name="username"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                      <saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                      <saml:Attribute Name="display_name"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
                    </saml:AttributeStatement>
                  </saml:Assertion>
                </samlp:Response>
                """.formatted(responseId, now, xml(acs), xml(requestId), xml(String.valueOf(idpConfig().get("entity_id"))),
                assertionId, now, xml(String.valueOf(idpConfig().get("entity_id"))), xml(ctx.identityId()),
                notAfter, xml(acs), xml(requestId), now.minusSeconds(60), notAfter, xml(audience),
                now, xml(ctx.sessionId() == null ? responseId : ctx.sessionId()),
                xml(String.valueOf(identity.get("username"))), xml(String.valueOf(identity.get("email"))),
                xml(String.valueOf(identity.get("display_name"))));
        String signed = signAssertion(responseXml, assertionId, assertionId);
        audit.log(ctx.tenantId(), ctx.identityId(), "saml.sso", "saml_sp", acs, "success", null, null,
                Map.of("issuer", issuer == null ? "" : issuer));
        return postBindingForm(acs, signed, params.get("RelayState"));
    }

    public Map<String, Object> slo(Map<String, String> params) {
        String request = params.get("SAMLRequest");
        String id = null;
        if (request != null) {
            try {
                Document document = parse(inflate(request));
                id = documentElement(document).getAttribute("ID");
            } catch (Exception ignored) {
            }
        }
        Map<String, Object> config = idpConfig();
        String response = """
                <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"
                    IssueInstant="%s" Destination="%s" InResponseTo="%s">
                  <saml:Issuer>%s</saml:Issuer>
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                </samlp:LogoutResponse>
                """.formatted(UUID.randomUUID(), Instant.now(), xml(params.get("RelayState") == null ? "" : params.get("RelayState")),
                xml(id == null ? "" : id), xml(String.valueOf(config.get("entity_id"))));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("redirect_uri", params.get("RelayState"));
        out.put("saml_response", deflate(response));
        return out;
    }

    public Map<String, Object> acs(String samlResponse, String relayState, SessionService.LoginMeta meta) {
        if (samlResponse == null) {
            throw ApiException.badRequest("缺少 SAMLResponse");
        }
        byte[] xmlBytes = Base64.getDecoder().decode(samlResponse.replaceAll("\\s", ""));
        Document document = parse(new String(xmlBytes, StandardCharsets.UTF_8));
        Element response = documentElement(document);
        String issuer = firstText(document, NS_ASSERTION, "Issuer");
        Map<String, Object> provider = db.list("""
                SELECT * FROM identity_providers WHERE kind = 'saml' AND (issuer = :issuer OR code = :issuer) AND enabled = TRUE
                """, Db.params("issuer", issuer == null ? "" : issuer)).stream().findFirst()
                .orElseThrow(() -> ApiException.badRequest("未配置的 SAML IdP"));
        Map<String, Object> config = Json.readMap(provider.get("config"));
        String certPem = str(config.get("idp_certificate_pem"));
        if (certPem == null) {
            throw ApiException.badRequest("SAML IdP 未配置签名证书");
        }
        verifySignature(document, parseCertificate(certPem));
        Element assertion = findSignedAssertion(document);
        if (assertion == null) {
            assertion = (Element) document.getElementsByTagNameNS(NS_ASSERTION, "Assertion").item(0);
        }
        if (assertion == null) {
            throw ApiException.badRequest("SAML 响应缺少 Assertion");
        }
        String assertionId = assertion.getAttribute("ID");
        Instant notOnOrAfter = Instant.parse(attr(assertion, "Conditions", "NotOnOrAfter", "9999-12-31T00:00:00Z"));
        if (notOnOrAfter.isBefore(Instant.now())) {
            throw ApiException.badRequest("SAML 断言已过期");
        }
        String audience = firstText((Document) assertion.getOwnerDocument(), NS_ASSERTION, "Audience");
        String expectedAudience = str(config.get("sp_entity_id"));
        if (expectedAudience != null && audience != null && !expectedAudience.equals(audience)) {
            throw ApiException.badRequest("SAML Audience 不匹配");
        }
        String recipient = firstAttribute(assertion, "SubjectConfirmationData", "Recipient");
        if (recipient != null && !recipient.equals(props.getBaseUrl() + "/api/v1/auth/federated/saml/acs")) {
            throw ApiException.badRequest("SAML Recipient 不匹配");
        }
        try {
            db.update("INSERT INTO saml_replay_cache (assertion_id, tenant_id, expires_at) VALUES (:id, :tenant, :exp)",
                    Db.params("id", assertionId, "tenant", provider.get("tenant_id"), "exp", notOnOrAfter.plusSeconds(60)));
        } catch (Exception e) {
            throw ApiException.badRequest("SAML 断言重放");
        }
        String subject = firstText((Document) assertion.getOwnerDocument(), NS_ASSERTION, "NameID");
        Map<String, String> attributes = attributes(assertion);
        String email = attributes.getOrDefault("email", attributes.get("mail"));
        String displayName = attributes.getOrDefault("display_name", attributes.get("name"));
        if (subject == null) {
            throw ApiException.badRequest("SAML 断言缺少 NameID");
        }
        Map<String, Object> external = db.list("""
                SELECT * FROM external_identities WHERE provider_id = :provider AND subject = :subject
                """, Db.params("provider", provider.get("id"), "subject", subject)).stream().findFirst().orElse(null);
        String identityId;
        if (external != null) {
            identityId = String.valueOf(external.get("identity_id"));
        } else {
            Map<String, Object> byEmail = email == null ? null : db.list("""
                    SELECT * FROM identities WHERE lower(email) = lower(:email) AND deleted_at IS NULL
                    """, Db.params("email", email)).stream().findFirst().orElse(null);
            if (byEmail != null && Boolean.TRUE.equals(provider.get("link_by_verified_email"))) {
                identityId = String.valueOf(byEmail.get("id"));
            } else if (Boolean.TRUE.equals(provider.get("auto_register"))) {
                String username = (email == null ? subject : email.split("@")[0]).replaceAll("[^A-Za-z0-9_.-]", "")
                        + "_" + Ids.randomDigits(4);
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("username", username);
                if (email != null) {
                    body.put("email", email);
                }
                body.put("display_name", displayName == null ? username : displayName);
                identityId = String.valueOf(identities.create(body, String.valueOf(provider.get("tenant_id")),
                        "active", meta, "saml").get("id"));
            } else {
                throw ApiException.forbidden("SAML 账号未绑定");
            }
            db.update("""
                    INSERT INTO external_identities (identity_id, provider_id, provider_code, subject, email, display_name, last_login_at)
                    VALUES (:identity, :provider, :code, :subject, :email, :name, now())
                    """, Db.params("identity", identityId, "provider", provider.get("id"),
                    "code", provider.get("code"), "subject", subject, "email", email, "name", displayName));
        }
        Map<String, Object> identity = identities.get(identityId);
        Map<String, Object> tokens = sessions.issue(identityId, String.valueOf(identity.get("tenant_id")),
                String.valueOf(provider.get("code")), "openid profile email offline_access",
                List.of("saml", "pwd"), "urn:auth:acr:saml", meta, null);
        audit.log(String.valueOf(identity.get("tenant_id")), identityId, "saml.acs", "identity_provider",
                String.valueOf(provider.get("code")), "success", meta.ip(), meta.userAgent(), Map.of());
        Map<String, Object> out = new LinkedHashMap<>(tokens);
        out.put("relay_state", relayState);
        return out;
    }

    public Map<String, Object> updateIdp(Map<String, Object> body) {
        Map<String, Object> config = idpConfig();
        db.update("""
                UPDATE saml_idp_configs SET enabled = COALESCE(:enabled, enabled),
                idp_name = COALESCE(:name, idp_name), metadata_xml = COALESCE(:metadata, metadata_xml),
                updated_at = now() WHERE tenant_id = :tenant
                """, Db.params("enabled", body.get("enabled"), "name", body.get("idp_name"),
                "metadata", body.get("metadata_xml"), "tenant", config.get("tenant_id")));
        return idpConfig();
    }

    public List<Map<String, Object>> listSps() {
        return db.list("""
                SELECT id, tenant_id, code, entity_id, name, acs_url, slo_url, audience, name_id_format,
                       attribute_mapping, status, created_at, updated_at
                FROM saml_sp_configs ORDER BY code
                """);
    }

    public Map<String, Object> upsertSp(Map<String, Object> body) {
        String code = String.valueOf(body.get("code"));
        db.update("""
                INSERT INTO saml_sp_configs
                (tenant_id, code, entity_id, name, metadata_xml, acs_url, slo_url, audience, name_id_format,
                 attribute_mapping, certificate_pem, status)
                VALUES (:tenant, :code, :entity, :name, :metadata, :acs, :slo, :audience, :format, :mapping, :cert, :status)
                ON CONFLICT (tenant_id, code) DO UPDATE SET
                    entity_id = EXCLUDED.entity_id, name = EXCLUDED.name, metadata_xml = EXCLUDED.metadata_xml,
                    acs_url = EXCLUDED.acs_url, slo_url = EXCLUDED.slo_url, audience = EXCLUDED.audience,
                    name_id_format = EXCLUDED.name_id_format, attribute_mapping = EXCLUDED.attribute_mapping,
                    certificate_pem = EXCLUDED.certificate_pem, status = EXCLUDED.status, updated_at = now()
                """, Db.params("tenant", body.getOrDefault("tenant_id", IdentityService.DEFAULT_TENANT),
                "code", code, "entity", body.getOrDefault("entity_id", code),
                "name", body.getOrDefault("name", code),
                "metadata", body.getOrDefault("metadata_xml", ""),
                "acs", body.get("acs_url"), "slo", body.get("slo_url"),
                "audience", body.getOrDefault("audience", body.getOrDefault("entity_id", code)),
                "format", body.getOrDefault("name_id_format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
                "mapping", Json.jsonb(body.getOrDefault("attribute_mapping", Map.of())),
                "cert", body.get("certificate_pem"), "status", body.getOrDefault("status", "active")));
        return db.one("SELECT * FROM saml_sp_configs WHERE code = :code", Db.params("code", code));
    }

    public void deleteSp(String code) {
        int count = db.update("DELETE FROM saml_sp_configs WHERE code = :code", Db.params("code", code));
        if (count == 0) {
            throw ApiException.notFound("SP 不存在");
        }
    }

    // ---------- 内部工具 ----------

    private String signAssertion(String xmlText, String assertionId, String referenceId) {
        try {
            Document document = parse(xmlText);
            Element assertion = (Element) document.getElementsByTagNameNS(NS_ASSERTION, "Assertion").item(0);
            assertion.setIdAttribute("ID", true);
            Map<String, Object> config = idpConfig();
            PrivateKey privateKey = parsePrivateKey(crypto.decrypt(String.valueOf(config.get("private_key_encrypted"))));
            PublicKey publicKey = parseCertificate(String.valueOf(config.get("certificate_pem"))).getPublicKey();
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            Reference reference = factory.newReference("#" + assertionId,
                    factory.newDigestMethod(DigestMethod.SHA256, null),
                    List.of(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                            factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)),
                    null, null);
            SignedInfo signedInfo = factory.newSignedInfo(
                    factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
            KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(List.of(keyInfoFactory.newKeyValue(publicKey)));
            DOMSignContext context = new DOMSignContext(privateKey, assertion);
            context.setDefaultNamespacePrefix("ds");
            factory.newXMLSignature(signedInfo, keyInfo).sign(context);
            return serialize(document);
        } catch (Exception e) {
            throw ApiException.internal("SAML 断言签名失败: " + e.getMessage());
        }
    }

    private void verifySignature(Document document, X509Certificate certificate) {
        try {
            NodeList signatures = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (signatures.getLength() == 0) {
                throw ApiException.badRequest("SAML 响应未签名");
            }
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            for (int i = 0; i < signatures.getLength(); i++) {
                Element signatureElement = (Element) signatures.item(i);
                Node parent = signatureElement.getParentNode();
                if (parent instanceof Element element && ("Assertion".equals(element.getLocalName())
                        || "Response".equals(element.getLocalName()))) {
                    element.setIdAttribute("ID", true);
                }
                DOMValidateContext context = new DOMValidateContext(certificate.getPublicKey(), signatureElement);
                context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
                XMLSignature signature = factory.unmarshalXMLSignature(context);
                if (signature.validate(context)) {
                    return;
                }
            }
            throw ApiException.badRequest("SAML 签名校验失败");
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.badRequest("SAML 签名校验失败");
        }
    }

    private Element findSignedAssertion(Document document) {
        NodeList signatures = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        for (int i = 0; i < signatures.getLength(); i++) {
            Node parent = signatures.item(i).getParentNode();
            if (parent instanceof Element element && "Assertion".equals(element.getLocalName())) {
                return element;
            }
        }
        return null;
    }

    private static Map<String, String> attributes(Element assertion) {
        Map<String, String> out = new LinkedHashMap<>();
        NodeList list = assertion.getElementsByTagNameNS(NS_ASSERTION, "Attribute");
        for (int i = 0; i < list.getLength(); i++) {
            Element attribute = (Element) list.item(i);
            String name = attribute.getAttribute("Name");
            NodeList values = attribute.getElementsByTagNameNS(NS_ASSERTION, "AttributeValue");
            if (values.getLength() > 0) {
                out.put(name, values.item(0).getTextContent());
            }
        }
        return out;
    }

    private static String firstText(Document document, String ns, String localName) {
        NodeList list = document.getElementsByTagNameNS(ns, localName);
        return list.getLength() == 0 ? null : list.item(0).getTextContent();
    }

    private static String firstAttribute(Element element, String localName, String attribute) {
        NodeList list = element.getElementsByTagNameNS(NS_ASSERTION, localName);
        if (list.getLength() == 0) {
            list = element.getElementsByTagNameNS(NS_PROTOCOL, localName);
        }
        if (list.getLength() == 0) {
            return null;
        }
        String value = ((Element) list.item(0)).getAttribute(attribute);
        return value == null || value.isBlank() ? null : value;
    }

    private static String attr(Element element, String localName, String attribute, String fallback) {
        NodeList list = element.getElementsByTagNameNS(NS_ASSERTION, localName);
        if (list.getLength() == 0) {
            return fallback;
        }
        String value = ((Element) list.item(0)).getAttribute(attribute);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static Document parse(String xmlText) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xmlText.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw ApiException.badRequest("XML 解析失败");
        }
    }

    private static Element documentElement(Document document) {
        return document.getDocumentElement();
    }

    private static String serialize(Document document) {
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            return writer.toString();
        } catch (Exception e) {
            throw ApiException.internal("XML 序列化失败");
        }
    }

    private static String inflate(String base64) {
        if (base64 == null) {
            throw ApiException.badRequest("缺少 SAMLRequest");
        }
        try {
            byte[] data = Base64.getDecoder().decode(base64.replaceAll("\\s", ""));
            Inflater inflater = new Inflater(true);
            inflater.setInput(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0 && inflater.needsInput()) {
                    break;
                }
                out.write(buffer, 0, count);
            }
            inflater.end();
            return out.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw ApiException.badRequest("SAMLRequest 解压失败");
        }
    }

    private static String deflate(String xmlText) {
        try {
            Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
            deflater.setInput(xmlText.getBytes(StandardCharsets.UTF_8));
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                out.write(buffer, 0, count);
            }
            deflater.end();
            return Base64.getEncoder().encodeToString(out.toByteArray());
        } catch (Exception e) {
            throw ApiException.internal("SAML 压缩失败");
        }
    }

    private static String postBindingForm(String acs, String samlResponse, String relayState) {
        String encoded = Base64.getEncoder().encodeToString(samlResponse.getBytes(StandardCharsets.UTF_8));
        return """
                <!DOCTYPE html><html><head><meta charset="utf-8"><title>SAML</title></head>
                <body onload="document.forms[0].submit()">
                <form method="post" action="%s">
                  <input type="hidden" name="SAMLResponse" value="%s"/>
                  %s
                  <noscript><button type="submit">Continue</button></noscript>
                </form></body></html>
                """.formatted(xml(acs), encoded,
                relayState == null ? "" : "<input type=\"hidden\" name=\"RelayState\" value=\"" + xml(relayState) + "\"/>");
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String selfSignedCertificate(KeyPair pair) throws Exception {
        X500Name subject = new X500Name("CN=Auth Center SAML Signing");
        Date from = new Date(System.currentTimeMillis() - 3600_000);
        Date to = new Date(System.currentTimeMillis() + 10L * 365 * 24 * 3600 * 1000);
        var builder = new JcaX509v3CertificateBuilder(subject,
                BigInteger.valueOf(System.currentTimeMillis()), from, to, subject, pair.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        return pem("CERTIFICATE", certificate.getEncoded());
    }

    private static String pemPrivateKey(KeyPair pair) {
        return pem("PRIVATE KEY", pair.getPrivate().getEncoded());
    }

    private static String pem(String type, byte[] data) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(data)
                + "\n-----END " + type + "-----";
    }

    private static X509Certificate parseCertificate(String pem) {
        try {
            byte[] data = Base64.getDecoder().decode(pem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", ""));
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(data));
        } catch (Exception e) {
            throw ApiException.badRequest("证书解析失败");
        }
    }

    private static PrivateKey parsePrivateKey(String pem) {
        try {
            byte[] data = Base64.getDecoder().decode(pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", ""));
            return java.security.KeyFactory.getInstance("RSA")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(data));
        } catch (Exception e) {
            throw ApiException.internal("私钥解析失败");
        }
    }

    private static String xml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
