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

import arrow.core.toNonEmptyListOrThrow
import eu.europa.ec.eudi.keycloak.ext.abca.trustvalidator.IsClientAttestationIssuerTrusted
import eu.europa.esig.dss.enumerations.CertificateSourceType
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.x509.CommonCertificateSource
import kotlinx.coroutines.runBlocking
import java.util.*

class CertificateSourceTrustValidator(private val trustValidator: IsClientAttestationIssuerTrusted) : CommonCertificateSource() {
    override fun isTrusted(certificateToken: CertificateToken): Boolean {
        val result = runBlocking {
            trustValidator(listOf(certificateToken.certificate).toNonEmptyListOrThrow())
        }
        return result
    }

    override fun getCertificateSourceType(): CertificateSourceType = CertificateSourceType.TRUSTED_STORE

    override fun isTrustedAtTime(certificateToken: CertificateToken, controlTime: Date): Boolean = isTrusted(certificateToken)
}
