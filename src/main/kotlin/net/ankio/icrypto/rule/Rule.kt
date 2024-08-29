package net.ankio.icrypto.rule

import kotlinx.serialization.Serializable

@Serializable
data class Rule(
    var name:String,
    var url:String,
    val command:String,
    var args: MutableMap<String, String> = mutableMapOf()
) {
    override fun toString(): String {
        return name
    }
}
