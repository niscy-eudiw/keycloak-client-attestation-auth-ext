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
import eu.europa.ec.eudi.keycloak.ext.abca.trustvalidator.TrustValidator
import eu.europa.esig.dss.jades.validation.JAdESSignature
import eu.europa.esig.dss.jades.validation.JWS
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier

/**
 * Verifies a Wallet Instance Attestation (WIA) as a JAdES signature conforming to the
 * JAdES-BASELINE-B profile, as defined by ETSI TS 119 182-1.
 *
 * Only the cryptographic signature integrity and the structural Baseline-B requirements are
 * checked here. Trust validation of the signing certificate chain is delegated to the
 * [TrustValidator] service, so no trust
 * store is configured on the [CommonCertificateVerifier] used to initialise the baseline
 * requirements checker.
 */

fun interface JadesBaseLineProfileVerifier {
    suspend fun verify(wia: JWT)
}

fun JadesBaseLineProfileVerifier(): JadesBaseLineProfileVerifier = JadesBaseLineProfileVerifier { wia ->
    val jwt = wia.serialize()
    val jws = JWS(jwt.split(".").toTypedArray())
    val signature = JAdESSignature(jws)

    // Cryptographic verification of the signature against the signing certificate from 'x5c'.
    signature.checkSignatureIntegrity()
    require(signature.signatureCryptographicVerification.isSignatureIntact) {
        "WIA signature verification failed"
    }

    // Structural conformance to the JAdES-BASELINE-B profile (ETSI TS 119 182-1).
    signature.initBaselineRequirementsChecker(CommonCertificateVerifier(true))
    signature.allEvidenceRecords
    require(signature.hasBProfile()) {
        "WIA does not conform to the JAdES-BASELINE-B profile"
    }
}
