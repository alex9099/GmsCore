/*
 * SPDX-FileCopyrightText: 2022 microG Project Team
 * SPDX-License-Identifier: Apache-2.0
 */

package org.microg.gms.fido.core.protocol.msgs


import com.upokecenter.cbor.CBORObject
import org.microg.gms.fido.core.protocol.encodeAsCbor
import java.security.spec.ECPoint

class AuthenticatorGetPinTokenCommand(request: AuthenticatorGetPinTokenRequest) :
    Ctap2Command<AuthenticatorGetPinTokenRequest, AuthenticatorGetPinTokenResponse>(request) {
    override fun decodeResponse(obj: CBORObject) = AuthenticatorGetPinTokenResponse.decodeFromCbor(obj)
    override val timeout: Long
        get() = 60000
}

class AuthenticatorGetPinTokenRequest(
        val platformPublicKey : ECPoint? = null,
        val encryptedPin : ByteArray? = ByteArray(1)
) : Ctap2Request(0x06, CBORObject.NewMap().apply {
    set(0x01, 1.encodeAsCbor())
    set(0x02, 0x05.encodeAsCbor())

    if (platformPublicKey != null) {
        //FIXME: use CoseKey
        set(0x03, CBORObject.NewMap().apply {
            set(1, 2.encodeAsCbor())
            set(3, (-25).encodeAsCbor())
            set(-1, 1.encodeAsCbor())
            //Platform EC public key coordinates
            set(-2, platformPublicKey.affineX.encodeAsCbor())
            set(-3, platformPublicKey.affineY.encodeAsCbor())
        })
    }
    set(0x06, encryptedPin?.encodeAsCbor())

}) {
    class Options(
    ) {
        override fun toString() = "AuthenticatorGetPinTokenRequest(pinUvAuthProtocol=1, subCommand(GetPinToken))"
    }
}

class AuthenticatorGetPinTokenResponse(
        val pinUvAuthToken: ByteArray?,
) : Ctap2Response {

    companion object {


        fun decodeFromCbor(obj: CBORObject) =
             AuthenticatorGetPinTokenResponse(
                //FIXME: use cosekey
                 pinUvAuthToken = obj.get(0x02).GetByteString(),
            )


        }
    }


