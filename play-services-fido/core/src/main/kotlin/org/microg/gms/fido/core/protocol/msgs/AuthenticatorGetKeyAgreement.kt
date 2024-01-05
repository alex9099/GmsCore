/*
 * SPDX-FileCopyrightText: 2022 microG Project Team
 * SPDX-License-Identifier: Apache-2.0
 */

package org.microg.gms.fido.core.protocol.msgs


import com.upokecenter.cbor.CBORObject
import org.microg.gms.fido.core.protocol.encodeAsCbor
import java.security.spec.ECPoint

class AuthenticatorGetKeyAgreementCommand(request: AuthenticatorGetKeyAgreementRequest) :
    Ctap2Command<AuthenticatorGetKeyAgreementRequest, AuthenticatorGetKeyAgreementResponse>(request) {
    override fun decodeResponse(obj: CBORObject) = AuthenticatorGetKeyAgreementResponse.decodeFromCbor(obj)
    override val timeout: Long
        get() = 60000
}

class AuthenticatorGetKeyAgreementRequest(

) : Ctap2Request(0x06, CBORObject.NewMap().apply {
    set(0x01, 1.encodeAsCbor())
    set(0x02, 0x02.encodeAsCbor())

}) {
    class Options(
    ) {
        override fun toString() = "AuthenticatorGetKeyAgreementRequest(pinUvAuthProtocol=1, subCommand(getKeyAgreement))"
    }
}

class AuthenticatorGetKeyAgreementResponse(
        val x: ByteArray?,
        val y: ByteArray?
) : Ctap2Response {

    companion object {


        fun decodeFromCbor(obj: CBORObject) =
             AuthenticatorGetKeyAgreementResponse(
                //FIXME: use cosekey
                x = obj.get(0x1).get(-2).GetByteString(),
                y = obj.get(0x1).get(-3).GetByteString()
            )


        }
    }

