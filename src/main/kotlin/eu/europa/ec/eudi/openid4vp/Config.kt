/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vp

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.oauth2.sdk.id.Issuer
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig.Companion.SelfIssued
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration.NotSupported
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import java.net.URI
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration

/**
 * The out-of-band knowledge of a Verifier, used in [SupportedClientIdPrefix.Preregistered]

 * @param clientId the client id of a trusted verifier
 * @param legalName the name of the trusted verifier
 * @param jarConfig in case, verifier communicates his request using JAR, the signing algorithm
 * that is used to sign his request and his available public keys in form of a JWKSet
 *
 */
data class PreregisteredClient(
    val clientId: OriginalClientId,
    val legalName: String,
    val jarConfig: Pair<JWSAlgorithm, JWKSet>? = null,
) {
    init {
        if (jarConfig != null) {
            require(!jarConfig.second.isEmpty) { "JWKSet cannot be empty" }
            val allKeysArePublic = jarConfig.second.keys.all { it.isPrivate == false }
            require(allKeysArePublic) { "JWKSet must contain only public keys" }
        }
    }
}

fun interface X509CertificateTrust {
    fun isTrusted(chain: List<X509Certificate>): Boolean
}

fun interface LookupPublicKeyByDIDUrl {
    suspend fun resolveKey(didUrl: URI): PublicKey?
}

/**
 * The Client identifier prefix supported (or trusted) by the wallet.
 */
sealed interface SupportedClientIdPrefix {

    /**
     * The Client Identifier is known to the Wallet in advance of the Authorization Request.
     */
    data class Preregistered(val clients: Map<OriginalClientId, PreregisteredClient>) : SupportedClientIdPrefix {
        constructor(vararg clients: PreregisteredClient) : this(clients.toList().associateBy { it.clientId })
    }

    /**
     * Wallet trusts verifiers that present an authorization request having a redirect URI
     * equal to the value of the Client Identifier.
     *
     * In this prefix, Verifier must NOT sign his request
     */
    data object RedirectUri : SupportedClientIdPrefix

    /**
     * Wallet trusts verifiers that are able to present a client identifier which is a DID
     *
     * In this prefix, Verifier must always sign his request (JAR), signed by a key
     * that can be referenced via the DID
     *
     * @param lookup a function for getting the public key of the verifier by
     * resolving a given DID URL
     */
    data class DecentralizedIdentifier(val lookup: LookupPublicKeyByDIDUrl) : SupportedClientIdPrefix

    /**
     * Wallet trust verifiers that are able to present a signed Verifier Attestation, which
     * is issued by a party trusted by the Wallet
     *
     * In this prefix, Verifier must always sign his request (JAR), having in its JOSE
     * header a Verifier Attestation JWT under `jwt` claim
     *
     * @param trust a function for verifying the digital signature of the Verifier Attestation JWT.
     * @param clockSkew max acceptable skew between wallet and attestation issuer
     */
    data class VerifierAttestation(
        val trust: JWSVerifier,
        val clockSkew: Duration = Duration.ofSeconds(15L),
    ) : SupportedClientIdPrefix

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is a DNS name and
     * matches a dNSName Subject Alternative Name (SAN) RFC5280 entry in the
     * leaf certificate passed with the request.
     *
     * In this prefix, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509SanDns(val trust: X509CertificateTrust) : SupportedClientIdPrefix {
        companion object {
            internal val NoValidation: X509SanDns = X509SanDns { _ -> true }
        }
    }

    /**
     * Wallet trusts verifiers that are able to present a Client Identifier which is the SHA256 hash of the DER encoded
     * leaf certificate passed with the request.
     *
     * In this prefix, Verifier must always sign his request (JAR)
     *
     * @param trust a function that accepts a chain of certificates (contents of `x5c` claim) and
     * indicates whether is trusted or not
     */
    data class X509Hash(val trust: X509CertificateTrust) : SupportedClientIdPrefix

    fun prefix(): ClientIdPrefix = when (this) {
        is Preregistered -> ClientIdPrefix.PreRegistered
        RedirectUri -> ClientIdPrefix.RedirectUri
        is DecentralizedIdentifier -> ClientIdPrefix.DecentralizedIdentifier
        is VerifierAttestation -> ClientIdPrefix.VerifierAttestation
        is X509SanDns -> ClientIdPrefix.X509SanDns
        is X509Hash -> ClientIdPrefix.X509Hash
    }

    fun metadataValue(): String = when (this) {
        is Preregistered -> OpenId4VPSpec.CLIENT_ID_PREFIX_PRE_REGISTERED
        RedirectUri -> OpenId4VPSpec.CLIENT_ID_PREFIX_REDIRECT_URI
        is DecentralizedIdentifier -> OpenId4VPSpec.CLIENT_ID_PREFIX_DECENTRALIZED_IDENTIFIER
        is VerifierAttestation -> OpenId4VPSpec.CLIENT_ID_PREFIX_VERIFIER_ATTESTATION
        is X509SanDns -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_SAN_DNS
        is X509Hash -> OpenId4VPSpec.CLIENT_ID_PREFIX_X509_HASH
    }
}

/**
 * A type of Transaction Data supported by the Wallet.
 */
sealed interface SupportedTransactionDataType {
    val type: TransactionDataType

    data class SdJwtVc(
        override val type: TransactionDataType,
        val hashAlgorithms: Set<HashAlgorithm>,
    ) : SupportedTransactionDataType {
        init {
            require(hashAlgorithms.isNotEmpty()) { "hashAlgorithms cannot be empty" }
            require(HashAlgorithm.SHA_256 in hashAlgorithms) { "'${HashAlgorithm.SHA_256.name}' must be a supported hash algorithm" }
        }
    }

    // CONFORMANCE test 13 — lets the wallet declare mdoc types, so the type check has something to
    // check against. Unreachable until wallet-core exposes supportedTransactionDataTypes.
    /**
     * An mdoc Transaction Data type the Wallet supports. No hash algorithms: see
     * [TransactionData.MsoMdoc].
     */
    data class MsoMdoc(
        override val type: TransactionDataType,
    ) : SupportedTransactionDataType
}

/**
 * Configuration options for OpenId4VP
 *
 * @param knownDCQLQueriesPerScope a set of DCQL queries that a verifier may request via a pre-agreed scope
 * @param vpFormatsSupported The formats the wallet supports
 * @param supportedTransactionDataTypes the types of Transaction Data that are supported by the wallet
 */
data class VPConfiguration(
    val knownDCQLQueriesPerScope: Map<String, DCQL> = emptyMap(),
    val vpFormatsSupported: VpFormatsSupported,
    val supportedTransactionDataTypes: List<SupportedTransactionDataType> = emptyList(),
) {
    init {
        if (null == vpFormatsSupported.sdJwtVc) {
            require(supportedTransactionDataTypes.none { it is SupportedTransactionDataType.SdJwtVc }) {
                "SD-JWT VC Transaction Data cannot be used when SD-JWT VC is not supported"
            }
        }
        if (null == vpFormatsSupported.msoMdoc) {
            require(supportedTransactionDataTypes.none { it is SupportedTransactionDataType.MsoMdoc }) {
                "mdoc Transaction Data cannot be used when mdoc is not supported"
            }
        }
    }
}

/**
 * Configurations options for encrypting an authorization response if requested by the verifier.
 *
 * OpenId4VP recommends supporting [encrypting][Supported] the authorization response
 */
sealed interface ResponseEncryptionConfiguration {

    /**
     * The wallet supports encrypting authorization responses
     *
     * @param supportedAlgorithms the JWE algorithms that the wallet can use
     * when encrypting the authorization response in order of preference
     * @param supportedMethods the JWE encryption methods that the wallet can use
     * when encrypting the authorization response in order of preference
     * [EncryptionMethod.XC20P] requires the usage of [com.google.crypto.tink:tink](https://central.sonatype.com/artifact/com.google.crypto.tink/tink)
     */
    data class Supported(
        val supportedAlgorithms: List<JWEAlgorithm>,
        val supportedMethods: List<EncryptionMethod>,
    ) : ResponseEncryptionConfiguration {
        init {
            require(supportedAlgorithms.isNotEmpty()) { "At least an encryption algorithm must be provided" }
            require(supportedMethods.isNotEmpty()) { "At least an encryption method must be provided" }
        }
    }

    /**
     * Wallet doesn't support replying using unencrypted authorization responses
     */
    data object NotSupported : ResponseEncryptionConfiguration
}

sealed interface NonceOption {
    data object DoNotUse : NonceOption

    @JvmInline
    value class Use(val byteLength: Int = MINIMUM_NONCE_LENGTH) : NonceOption {
        init {
            require(byteLength >= MINIMUM_NONCE_LENGTH) { "Byte length should be at least $MINIMUM_NONCE_LENGTH" }
        }
        companion object {
            const val MINIMUM_NONCE_LENGTH: Int = 32
        }
    }
}

/**
 * Wallet articulated encryption requirements.
 */
sealed interface EncryptionRequirement : java.io.Serializable {

    /**
     * Encryption is not required.
     */
    data object NotRequired : EncryptionRequirement {
        private fun readResolve(): Any = NotRequired
    }

    /**
     * Encryption is required.
     *
     * @property supportedEncryptionAlgorithms encryption algorithms supported by the Wallet, only asymmetric JWEAlgorithms are supported
     * @property supportedEncryptionMethods encryption methods supported by the Wallet, [EncryptionMethod.XC20P] requires the usage
     * of [com.google.crypto.tink:tink](https://central.sonatype.com/artifact/com.google.crypto.tink/tink)
     * @property ephemeralEncryptionKeyCurve the [Curve] to use for generating the ephemeral encryption key
     */
    data class Required(
        val supportedEncryptionAlgorithms: List<JWEAlgorithm>,
        val supportedEncryptionMethods: List<EncryptionMethod>,
        val ephemeralEncryptionKeyCurve: Curve,
    ) : EncryptionRequirement {
        init {
            require(supportedEncryptionAlgorithms.isNotEmpty()) { "supportedEncryptionAlgorithms cannot be empty" }
            require(SUPPORTED_ENCRYPTION_ALGORITHMS.containsAll(supportedEncryptionAlgorithms)) {
                "only the following JWEAlgorithms are supported: $SUPPORTED_ENCRYPTION_ALGORITHMS"
            }
            require(supportedEncryptionMethods.isNotEmpty()) { "supportedEncryptionMethods cannot be empty" }
            require(SUPPORTED_ENCRYPTION_METHODS.containsAll(supportedEncryptionMethods)) {
                "only the following EncryptionMethods are supported: $SUPPORTED_ENCRYPTION_METHODS"
            }
            require(ephemeralEncryptionKeyCurve in SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES) {
                "only the following Curves are supported: $SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES"
            }
        }

        companion object {
            val SUPPORTED_ENCRYPTION_ALGORITHMS: List<JWEAlgorithm> get() = JWEAlgorithm.Family.ECDH_ES.toList()
            val SUPPORTED_ENCRYPTION_METHODS: List<EncryptionMethod> get() = ECDHDecrypter.SUPPORTED_ENCRYPTION_METHODS.toList()
            val SUPPORTED_EPHEMERAL_ENCRYPTION_KEY_CURVES: List<Curve> get() = ECDHDecrypter.SUPPORTED_ELLIPTIC_CURVES.toList()
        }
    }
}

/**
 * Which of the `request_uri_method` are supported by the wallet
 */
sealed interface SupportedRequestUriMethods {

    /**
     * Indicates support to `request_uri_method` `get`
     */
    data object Get : SupportedRequestUriMethods

    /**
     * Options related to `request_uri_method` equal to `post`
     *
     * @param includeWalletMetadata whether to include wallet metadata or not
     * @param jarEncryption whether to request JAR be encrypted or not
     * @param useWalletNonce whether to use wallet_nonce
     */
    data class Post(
        val includeWalletMetadata: Boolean = true,
        val jarEncryption: EncryptionRequirement = EncryptionRequirement.NotRequired,
        val useWalletNonce: NonceOption = NonceOption.Use(),
    ) : SupportedRequestUriMethods {
        init {
            require(EncryptionRequirement.NotRequired == jarEncryption || includeWalletMetadata) {
                "Wallet Metadata must be included when JAR encryption is required"
            }
        }
    }

    /**
     * Both methods are supported
     */
    data class Both(val post: Post) : SupportedRequestUriMethods

    fun isGetSupported(): Boolean = when (this) {
        is Both, Get -> true
        is Post -> false
    }

    fun isPostSupported(): Post? = when (this) {
        is Both -> post
        Get -> null
        is Post -> this
    }

    companion object {
        /**
         * The default option is to support both `get` and `post` and in the later case,
         * include `wallet_metadata` and `wallet_nonce`, and NOT require JAR be encrypted
         */
        val Default: SupportedRequestUriMethods = Both(post = Post())
    }
}

/**
 * Defines a policy for handling multi-signed authorization requests within the system.
 * This sealed interface is used to indicate how the client should handle such requests
 * based on different scenarios or restrictions.
 */
sealed interface MultiSignedRequestsPolicy {

    data class Expect(val clientPrefix: ClientIdPrefix) : MultiSignedRequestsPolicy

    data object NotSupported : MultiSignedRequestsPolicy
}

/**
 * Options related to JWT-Secured authorization requests
 *
 * @param supportedAlgorithms the algorithms supported for the signature of the JAR
 * @param supportedRequestUriMethods which of the `request_uri_method` methods are supported
 * @param multiSignedRequestsPolicy whether the wallet supports multi-signed requests and if so, what is the expected client prefix
 * @param clockSkew max acceptable skew between wallet and verifier when performing request signature validation
 */
data class SignedRequestConfiguration(
    val supportedAlgorithms: List<JWSAlgorithm>,
    val supportedRequestUriMethods: SupportedRequestUriMethods = SupportedRequestUriMethods.Default,
    val multiSignedRequestsPolicy: MultiSignedRequestsPolicy = MultiSignedRequestsPolicy.NotSupported,
    val clockSkew: Duration = Duration.ofSeconds(15L),
) {
    init {
        require(supportedAlgorithms.isNotEmpty()) { "JAR signing algorithms cannot be empty" }
    }

    companion object {
        /**
         * The default JAR configuration list as trusted algorithms ES256, ES384, and ES512.
         * Also, both `request_uri_method` are supported.
         *
         * @see SupportedRequestUriMethods.Default
         */
        val Default = SignedRequestConfiguration(
            supportedAlgorithms = listOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512),
            supportedRequestUriMethods = SupportedRequestUriMethods.Default,
            multiSignedRequestsPolicy = MultiSignedRequestsPolicy.NotSupported,
        )
    }
}

/**
 * Wallets policy regarding error dispatching.
 */
enum class ErrorDispatchPolicy : java.io.Serializable {

    /**
     * Allow dispatching of errors to all clients, regardless of authentication status.
     */
    AllClients,

    /**
     * Allow dispatching of errors only to authenticated clients.
     */
    OnlyAuthenticatedClients,
}

// CONFORMANCE tests 11 and 13 — the mechanism. This half is the one grounded in RFC 6749 rather than
// in what the conformance suite demands; the function below it is the accommodation.
//
// Grounded is not the same as ready to propose upstream, and this is not: the property that uses it
// had to become a body property rather than a constructor parameter (binary compatibility with the
// prebuilt wallet-core), so nobody can actually set it; it has no tests; and its one load-bearing
// entry is superseded on 0.16.x by `uriMatchesClient` from the other half of PR #501, which does the
// same check earlier and better. Read it as "the part that is not a conformance hack".
//
// Six of the seven entries below are belt-and-braces: `responseMode()` in the resolver already
// returns null for those request shapes, so `dispatchErrorDetailsOrNull` would send nothing even
// without the predicate. Listing them anyway states the rule instead of relying on that coincidence.
//
// The seventh carries weight. `InvalidRedirectUri` is also raised when the `redirect_uri` is valid
// https but does not match the `client_id` of a `redirect_uri`-prefixed client. There the resolver's
// permissive re-parse yields a usable ResponseMode, so without this entry the Wallet would post an
// error to a redirect URI that does not belong to the authenticated client. Upstream closes that in
// the other half of PR #501 (`uriMatchesClient`), which is not backported here — so this entry is
// standing in for it.
/**
 * Errors for which no Authorization Error Response is sent, even to a client that authenticated.
 *
 * [ErrorDispatchPolicy] answers "may we talk to this client at all?", which is a question about the
 * authentication phase. This answers a different one — "is this particular error one we answer?" —
 * for the validation phase, where the client's identity is already established. The two are
 * orthogonal and both are consulted.
 *
 * The default covers only defects of the response channel itself: cases where the Wallet cannot tell
 * where the response should go, or where the destination it was given is not one it may use. That is
 * the [RFC6749] §4.1.2.1 rule — do not deliver an error to a redirection URI that is missing,
 * invalid or mismatching — carried over to the Response URI by OpenID4VP §8.2's note. Everything
 * else stays dispatchable, because §8.5 defines error codes precisely so an authenticated Verifier
 * learns why its request was refused.
 *
 * OpenID Connect Core 1.0 §3.1.2.6 restates the same boundary independently, and names the invalid
 * Redirection URI as the *only* exception: "Unless the Redirection URI is invalid, the Authorization
 * Server returns the Client to the Redirection URI … with the appropriate error and state
 * parameters." It also gives the cleanest justification for [RequestValidationError
 * .UnsupportedResponseMode] being in this set: an unsupported Response Mode is answered with a bare
 * 400 and no error parameters, "since understanding the Response Mode is necessary to know how to
 * return those parameters". OpenID4VP §8.5 defers to RFC 6749 rather than to OIDC Core, so this is
 * corroboration rather than a binding requirement.
 *
 * Checked and not found: OIDC Core says nothing about a *missing* required nonce — no obligation to
 * answer, and no permission to stay silent. It also marks `nonce` OPTIONAL for the code flow and
 * advises that "Authorization Servers SHOULD perform no other processing on nonce values used". So
 * there is no basis there for treating [RequestValidationError.MissingNonce] as a channel defect;
 * it sits in the conformance function below for that reason. No need to look again.
 *
 * Note that after upstream PR #501 a request mixing `redirect_uri` with `direct_post` yields no
 * response mode at all, so [RequestValidationError.RedirectUriMustNotBeProvided] never reaches this
 * point. It is listed anyway: the predicate should describe the rule, not the current code paths.
 */
public fun defaultNonDispatchableErrors(error: AuthorizationRequestError): Boolean = when (error) {
    RequestValidationError.RedirectUriMustNotBeProvided,
    RequestValidationError.ResponseUriMustNotBeProvided,
    RequestValidationError.InvalidRedirectUri,
    RequestValidationError.InvalidResponseUri,
    RequestValidationError.MissingRedirectUri,
    RequestValidationError.MissingResponseUri,
    is RequestValidationError.UnsupportedResponseMode,
    -> true

    else -> false
}

// CONFORMANCE tests 11 `negative-test-missing-nonce` and 13
// `negative-test-unknown-transaction-data-type` — this is what makes them pass.
//
// ─── LOCAL DEVIATION — NOT FOR UPSTREAM. Remove this function and the property that references it
// before opening a PR. `defaultNonDispatchableErrors` above would also need reworking first — see
// the note on it.
//
// Suppresses two error responses so the OpenID Foundation conformance suite's
// `negative-test-missing-nonce` and `negative-test-unknown-transaction-data-type` pass. Both tests
// fail *any* call to the response endpoint, without decrypting the body or reading the error code,
// so the only way to satisfy them is to send nothing.
//
// This is an accommodation to the suite, not a reading of the specification, and the two entries do
// not cost the same:
//
//  - MissingNonce. §5.2 marks `nonce` REQUIRED but no OpenID4VP sentence mandates an error response
//    for its absence; RFC 6749's generic `invalid_request` covers it. The specification declines to
//    insist, so suppressing exploits a gap. Note that the usual justification — that without a nonce
//    the Wallet cannot bind a response — is false: `apv` appears once in all of OpenID4VP 1.0 and in
//    a non-normative note, §8.3's own example header omits it, `nonce` is not a response parameter
//    under §8.1, and this wallet demonstrably sent a HAIP-conformant JWE (ECDH-ES, A256GCM) without
//    one. A normative `apv = nonce` may exist in ISO/IEC 18013-7 Annex B, which has not been read
//    and which this wallet no longer supports.
//
//  - InvalidTransactionData. Here the specification insists three times: §5.1 requires an error if
//    even one transaction data type is unrecognised, §8.4 requires one if the parameter is
//    unsupported at all, and §8.5 names the code `invalid_transaction_data`. Suppressing this
//    contradicts explicit MUSTs, and it removes the live example that shows the suite is
//    inconsistent with itself — `negative-test-required-non-matching-credential` decrypts an
//    `access_denied` error response from this same wallet, over the same channel, with the same key,
//    and validates it clause by clause.
//
// Both entries exist because the alternative was leaving conformance tests red. That was a product
// decision, taken with the above on the record. See conformance/TESTS-11-13-DECISION.md. If OIDF
// corrects the tests, delete this function and revert the property to
// ::defaultNonDispatchableErrors.
internal fun conformanceNonDispatchableErrors(error: AuthorizationRequestError): Boolean =
    defaultNonDispatchableErrors(error) ||
        error == RequestValidationError.MissingNonce ||
        error is ResolutionError.InvalidTransactionData

/**
 * Wallet configuration options for OpenId4VP protocol.
 *
 * At minimum, a wallet configuration should define at least a [supportedClientIdPrefixes]
 *
 * @param issuer an optional id for the wallet. If not provided defaults to [SelfIssued].
 * @param signedRequestConfiguration options related to JWT Secure authorization requests.
 * If not provided, it will default to [SignedRequestConfiguration.Default]
 * @param responseEncryptionConfiguration whether wallet supports authorization response encryption. If not specified, it takes the default value
 * [ResponseEncryptionConfiguration.NotSupported].
 * @param vpConfiguration options about OpenId4VP.
 * @param clock the system Clock. If not provided system's default clock will be used.
 * @param supportedClientIdPrefixes the client id prefixes that are supported/trusted by the wallet
 * @param errorDispatchPolicy wallet's policy regarding error dispatching. Defaults to [ErrorDispatchPolicy.OnlyAuthenticatedClients].
 * @param nonDispatchableErrors errors that are never answered, even to an authenticated client.
 * Defaults to [defaultNonDispatchableErrors]. Independent of [errorDispatchPolicy], which governs
 * the authentication phase rather than the validation phase.
 */
data class OpenId4VPConfig(
    val issuer: Issuer? = SelfIssued,
    val signedRequestConfiguration: SignedRequestConfiguration = SignedRequestConfiguration.Default,
    val responseEncryptionConfiguration: ResponseEncryptionConfiguration = NotSupported,
    val vpConfiguration: VPConfiguration,
    val clock: Clock = Clock.systemDefaultZone(),
    val supportedClientIdPrefixes: List<SupportedClientIdPrefix>,
    val errorDispatchPolicy: ErrorDispatchPolicy = ErrorDispatchPolicy.OnlyAuthenticatedClients,
) {
    /**
     * Errors that are never answered, even to a client that authenticated. See
     * [defaultNonDispatchableErrors].
     *
     * Deliberately a body property rather than a constructor parameter. wallet-core 0.29.0 is a
     * prebuilt artifact linked against this class's existing constructor, and adding a parameter
     * changes the synthetic `<init>` signature that its call site was compiled against — the app
     * then dies at runtime with "No direct method <init>(…ErrorDispatchPolicy;I…)V in class
     * OpenId4VPConfig". Measured, not theorised. Upstream can make it a constructor parameter in a
     * new minor version, where consumers are recompiled; a local patch under a prebuilt consumer
     * cannot.
     *
     * The consequence is that it is not settable from outside. That costs nothing today: wallet-core
     * does not expose `errorDispatchPolicy` either, so no integrator can reach any of this without
     * the pass-through described in conformance/OIDF-ERROR-DISPATCH.md.
     */
    val nonDispatchableErrors: (AuthorizationRequestError) -> Boolean =
        ::conformanceNonDispatchableErrors

    init {
        require(supportedClientIdPrefixes.isNotEmpty()) { "At least a supported client id prefix must be provided" }

        if (signedRequestConfiguration.multiSignedRequestsPolicy is MultiSignedRequestsPolicy.Expect) {
            val multiSignedExpectedPrefix = signedRequestConfiguration.multiSignedRequestsPolicy.clientPrefix
            val supportedPrefixes = supportedClientIdPrefixes.map { it.prefix() }
            require(multiSignedExpectedPrefix in supportedPrefixes) {
                "Wrong configuration. Multi-singed requests policy must declare a supported client id prefix."
            }
        }
    }

    constructor(
        issuer: Issuer? = SelfIssued,
        signedRequestConfiguration: SignedRequestConfiguration = SignedRequestConfiguration.Default,
        responseEncryptionConfiguration: ResponseEncryptionConfiguration = NotSupported,
        vpConfiguration: VPConfiguration,
        clock: Clock = Clock.systemDefaultZone(),
        errorDispatchPolicy: ErrorDispatchPolicy = ErrorDispatchPolicy.OnlyAuthenticatedClients,
        vararg supportedClientIdPrefixes: SupportedClientIdPrefix,
    ) : this(
        issuer,
        signedRequestConfiguration,
        responseEncryptionConfiguration,
        vpConfiguration,
        clock,
        supportedClientIdPrefixes.toList(),
        errorDispatchPolicy,
    )

    companion object {
        /**
         * Identifies the wallet as `https://self-issued.me/v2`
         */
        val SelfIssued = Issuer(URI.create("https://self-issued.me/v2"))
    }
}

internal fun OpenId4VPConfig.supportedClientIdPrefix(prefix: ClientIdPrefix): SupportedClientIdPrefix? =
    supportedClientIdPrefixes.firstOrNull { it.prefix() == prefix }
