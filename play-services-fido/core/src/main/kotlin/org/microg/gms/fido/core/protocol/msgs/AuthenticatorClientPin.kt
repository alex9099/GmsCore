/*
 * SPDX-FileCopyrightText: 2022 microG Project Team
 * SPDX-License-Identifier: Apache-2.0
 */

package org.microg.gms.fido.core.protocol.msgs


import com.upokecenter.cbor.CBORObject
import org.microg.gms.fido.core.protocol.encodeAsCbor
import java.security.spec.ECPoint

class AuthenticatorClientPinCommand(request: AuthenticatorClientPinRequest) :
    Ctap2Command<AuthenticatorClientPinRequest, AuthenticatorClientPinResponse>(request) {
    override fun decodeResponse(obj: CBORObject) = AuthenticatorClientPinResponse.decodeFromCbor(obj)
    override val timeout: Long
        get() = 60000
}

class AuthenticatorClientPinRequest(
        val getKeyAgreement : Boolean,
        val platformPublicKey : ECPoint? = null,
        val encryptedPin : ByteArray? = ByteArray(1)

) : Ctap2Request(0x06, CBORObject.NewMap().apply {
    set(0x01, 1.encodeAsCbor())
    if (getKeyAgreement) set(0x02, 0x02.encodeAsCbor()) else {
        set(0x02, 0x05.encodeAsCbor())

        if (platformPublicKey != null) {
            //FIXME: use CoseKey
            set(0x03, CBORObject.NewMap().apply {
                set(1, 2.encodeAsCbor())
                set(3, (-25).encodeAsCbor())
                set(-1, 1.encodeAsCbor())
                set(-2, platformPublicKey.affineX.encodeAsCbor())
                set(-3, platformPublicKey.affineY.encodeAsCbor())
            })
        }
        set(0x06, encryptedPin?.encodeAsCbor())
    }

}) {
    class Options(
    ) {
        override fun toString() = "AuthenticatorClientPinRequest(pinUvAuthProtocol=1, subCommand(getKeyAgreement))"
    }
}

class AuthenticatorClientPinResponse(
        val x: ByteArray?,
        val y: ByteArray?
) : Ctap2Response {

    companion object {


        fun decodeFromCbor(obj: CBORObject) =
             AuthenticatorClientPinResponse(
                //FIXME: use cosekey
                x = obj.get(0x1).get(-2).GetByteString(),
                y = obj.get(0x1).get(-3).GetByteString()
            )


        }
    }

