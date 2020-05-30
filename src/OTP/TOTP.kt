package OTP

import java.nio.ByteBuffer
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import kotlin.experimental.and
import com.google.common.io.BaseEncoding
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

class TOTP(val secretKey: SecretKey,
           _passwordLength: Int = 6,
           _hmacAlgorithm: String = HmacAlgorithms.HmacSHA1.toString()
) {
    val passwordLength: Int = when(_passwordLength) {
        in 6..8 -> _passwordLength
        else -> 6
    }
    val hmacAlgorithm: String =
            if (enumContains<OTP.HmacAlgorithms>(_hmacAlgorithm)) _hmacAlgorithm
            else { HmacAlgorithms.HmacSHA1.toString() }

    private val debutUnixTime = 0
    private var currentUnixTime = { System.currentTimeMillis() / 1000 }
    private val timeStep = 30
    private var countTimeSteps = { (currentUnixTime() - debutUnixTime) / timeStep }

    private fun hasher(timeStamp: Long): ByteArray {
        var hashGenerator = Mac.getInstance(hmacAlgorithm)
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
        return binary.int.rem(10.0.pow(passwordLength).toInt()).toString()
    }

    fun generateOTP(timeStamp: Long = countTimeSteps()): String {
        var hash = hasher(timeStamp)
        var otpCode = truncateHash(hash)
        while (passwordLength > otpCode.length) otpCode = "0$otpCode"
        return otpCode
    }
}

enum class HmacAlgorithms() {
    HmacSHA1,
    HmacSHA256,
    HmacSHA512;
}

inline fun <reified T : Enum<T>> enumContains(algorithm: String): Boolean {
    return enumValues<T>().any { it.name == algorithm }
}