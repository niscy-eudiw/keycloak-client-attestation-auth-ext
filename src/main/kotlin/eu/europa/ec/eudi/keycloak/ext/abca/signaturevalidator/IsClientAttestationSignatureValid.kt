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
package eu.europa.ec.eudi.keycloak.ext.abca.signaturevalidator

import arrow.core.raise.result
import com.nimbusds.jose.crypto.ECDSAVerifier
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientAttestation
import kotlin.time.Clock

fun interface IsClientAttestationSignatureValid : suspend (ClientAttestation) -> SignatureVerificationResult {

    companion object {
        val Ignored: IsClientAttestationSignatureValid = { _ -> SignatureVerificationResult.Passed }

        fun jadesBB(clock: Clock, jadesValidator: JadesBaseLineBVerifier): IsClientAttestationSignatureValid = { clientAttestation ->
            jadesValidator.verify(clientAttestation, clock)
        }

        fun jws(): IsClientAttestationSignatureValid = { clientAttestation ->
            val signingKey = clientAttestation.signingKey
            result {
                if (clientAttestation.jwt.verify(ECDSAVerifier(signingKey))) {
                    SignatureVerificationResult.Passed
                } else {
                    SignatureVerificationResult.Failed("Client Attestation failed signature verification")
                }
            }.getOrElse {
                SignatureVerificationResult.Failed("Client Attestation failed signature verification", it)
            }
        }
    }
}
