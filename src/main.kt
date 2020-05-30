import OTP.TOTP
import com.google.common.io.BaseEncoding
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

fun generateSecretKey(): SecretKey {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    return keyGenerator.generateKey()
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
    val totp: TOTP = if(secretKey != null) TOTP(secretKey) else TOTP(generateSecretKey())
    println(totp.generateOTP())
}