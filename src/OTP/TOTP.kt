package OTP

import java.nio.ByteBuffer
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import kotlin.experimental.and
import com.google.common.io.BaseEncoding
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

const val PASSWORD_LENGTH: Int = 6

fun generateSecretKey(): SecretKey {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    return keyGenerator.generateKey()
}

class TOTP(val secretKey: SecretKey = generateSecretKey()) {
    private val debutUnixTime = 0
    private var currentUnixTime = { System.currentTimeMillis() / 1000 }
    private val timeStep = 30
    private var countTimeSteps = (currentUnixTime() - debutUnixTime) / timeStep

    private fun hasher(timeStamp: Long): ByteArray {
        var hashGenerator = Mac.getInstance(HmacAlgorithms.HmacSHA1.toString())
        hashGenerator.init(secretKey)
        return hashGenerator.doFinal(timeStamp.toString().toByteArray())
    }

    private fun truncateHash(timeHash: ByteArray): String {
        var offset: Int = timeHash.last().and(0x0F).toInt()
        val binary = ByteBuffer.allocate(4).apply {
            for (i in 0..3) {
                put(i, timeHash[i + offset])
            }
        }
        binary.put(0, binary.get(0).and(0x7F))
        return binary.int.rem(10.0.pow(PASSWORD_LENGTH).toInt()).toString()
    }

    fun generateOTP(timeStamp: Long = countTimeSteps): String {
        var hash = hasher(timeStamp)
        var otpCode = truncateHash(hash)
        while (PASSWORD_LENGTH > otpCode.length) otpCode = "0$otpCode"
        return otpCode
    }
}

fun main () {
    var secretKey: SecretKey? = null
    println("Do you have a secret? (y/n) -> ")
    when (readLine() ?: false) {
        "y" -> {
            println("Input the base32 Secret provided to you: ")
            val base32SecretKey = BaseEncoding.base32().decode(readLine())
            secretKey = SecretKeySpec(base32SecretKey, "AES")
        }
        else -> println("A secret will be automatically created for the OTP generation")
    }
    val totp: TOTP = if(secretKey != null) TOTP(secretKey) else TOTP()
    println(totp.generateOTP())
}

enum class HmacAlgorithms() {
    HmacSHA1,
    HmacSHA256,
    HmacSHA512;
}
