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
package eu.europa.ec.eudi.keycloak.ext.abca.jadesvalidator

import com.nimbusds.jwt.JWT
import eu.europa.ec.eudi.keycloak.ext.abca.trustvalidator.IsClientAttestationIssuerTrusted
import eu.europa.ec.eudi.keycloak.ext.abca.trustvalidator.TrustValidator
import eu.europa.esig.dss.enumerations.Indication
import eu.europa.esig.dss.enumerations.ValidationLevel
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor
import eu.europa.esig.dss.spi.x509.CertificateSource
import eu.europa.esig.dss.spi.x509.CommonCertificateSource
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.validation.SignedDocumentValidator
import java.security.cert.X509Certificate
import java.util.*
import kotlin.time.Clock
import kotlin.time.toJavaInstant

/**
 * Verifies a Wallet Instance Attestation (WIA) as a JAdES signature conforming to the
 * JAdES-BASELINE-B profile
 *
 * Only the cryptographic signature integrity and the structural Baseline-B requirements are
 * checked here. Trust validation of the signing certificate chain is delegated to the
 * [TrustValidator] service, so no trust
 * store is configured on the [CommonCertificateVerifier] used to initialise the baseline
 * requirements checker.
 */

fun interface JadesBaseLineProfileVerifier {
    suspend fun verify(wia: JWT, clock: Clock, x5c: X509Certificate)
}

fun JadesBaseLineProfileVerifier(): JadesBaseLineProfileVerifier = JadesBaseLineProfileVerifier { wia, clock, x5c ->

    val certificateVerifier: CommonCertificateVerifier = CommonCertificateVerifier(true).apply {
        val certificateSource: CertificateSource = CommonCertificateSource().apply { addCertificate(CertificateToken(x5c)) }
        val trustedCertificateSource = CommonTrustedCertificateSource().apply { importAsTrusted(certificateSource) }

        setTrustedCertSources(trustedCertificateSource)
    }

    val validator =
        SignedDocumentValidator.fromDocument(InMemoryDocument(wia.serialize().toByteArray())).apply {
            setCertificateVerifier(certificateVerifier)
            setValidationLevel(ValidationLevel.BASIC_SIGNATURES)
            setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE)
            setValidationTime(Date.from(clock.now().toJavaInstant()))
        }

    val report = validator.validateDocument().simpleReport
    check(null != report.signatureIdList.singleOrNull()) { "JWT can not contain more than one signature" }

    val signatureId = report.firstSignatureId
    val indication = report.getIndication(signatureId)
    if (indication == Indication.TOTAL_PASSED) {
        return@JadesBaseLineProfileVerifier
    } else {
        throw IllegalStateException(
            "JAdES B-B signature verification failed: indication=$indication, " +
                "subIndication=${report.getSubIndication(signatureId)}",
        )
    }
}
