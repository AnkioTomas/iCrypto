import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.ankio.icrypto.BurpExtender
import net.ankio.icrypto.rule.Rule

@Serializable
data class Config(var auto: Boolean, var list: ArrayList<Rule>) {
///usr/local/bin/node /Users/ankio/Downloads/debug_-1298305117_2_-1209654144/sm4.cjs
    companion object {
        fun load(): Config {
            try {
                val jsonString = BurpExtender.callbacks.loadExtensionSetting("Setting")

                if (jsonString.isNotBlank()) { // 添加空字符串检查
                    return Json.decodeFromString<Config>(jsonString)
                }
            } catch (e: Exception) {
                // 在此处理反序列化时可能出现的异常
                e.printStackTrace()
                BurpExtender.stderr.println("配置加载失败")
                BurpExtender.stderr.println(e)
            }
            return Config(false, ArrayList())
        }
        fun save(config: Config){
            val jsonString = Json.encodeToString(config)
            BurpExtender.callbacks.saveExtensionSetting("Setting", jsonString)
        }
    }

    fun add(rule: Rule) {
        BurpExtender.stdout.println("保存" + rule.name)
        val index = list.indexOfFirst { it.name == rule.name }
        if (index == -1) {
            BurpExtender.stdout.println("新增" + rule.name)
            list.add(rule)
        } else {
            BurpExtender.stdout.println("更新" + rule.name)
            list[index] = Rule(rule.name, rule.url, rule.command, rule.args)
        }

        save(this)
    }

    fun del(index:Int){
        list.removeAt(index)
        save(this)
    }

    fun find(url: String): Rule? {
        return list.find { url.contains(it.url) }
    }

        // 新增的 update 方法
    fun update(rule: Rule) {
        val existingRule = list.find { it.command == rule.command }
        if (existingRule != null) {
            existingRule.name = rule.name
            existingRule.url = rule.url
            existingRule.args = rule.args
            BurpExtender.stdout.println("更新并保存 " + rule.name)
        } else {
            BurpExtender.stderr.println("未找到匹配的规则来更新: " + rule.command)
        }
        save(this)  // 这里直接保存更新后的配置
    }
}