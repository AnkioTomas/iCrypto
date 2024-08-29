package net.ankio.icrypto.registers

import burp.IHttpListener
import burp.IHttpRequestResponse
import burp.IInterceptedProxyMessage
import burp.IProxyListener
import net.ankio.icrypto.BurpExtender
import net.ankio.icrypto.http.Cache
import net.ankio.icrypto.http.HttpAgreementRequest
import net.ankio.icrypto.http.HttpAgreementResponse
import net.ankio.icrypto.rule.CommandType
import net.ankio.icrypto.rule.Execution
import java.io.IOException

class HttpListener internal constructor() : IHttpListener, IProxyListener {
    private var httpAgreementRequest: HttpAgreementRequest? = null
    private var httpAgreementResponse: HttpAgreementResponse? = null

    @Throws(IOException::class)
    private fun analyze(
        messageInfo: IHttpRequestResponse,
        messageIsRequest: Boolean,
        cmd: Array<String?>,
        cache: Cache
    ): Pair<Boolean, Map<String, String>> {
        if (!BurpExtender.config.auto) {
            return Pair(false, emptyMap())
        }

        // 获取完整的 URL
        val requestInfo = BurpExtender.callbacks.helpers.analyzeRequest(messageInfo)
        var url = requestInfo.url.toString()

        // 移除默认的80 443 端口
        url = removeDefaultPort(url)

        val rule = BurpExtender.config.find(url) ?: return Pair(false, emptyMap())

        // 创建请求和响应对象
        httpAgreementRequest = HttpAgreementRequest(messageInfo.request, cache)
        if (!messageIsRequest) {
            httpAgreementResponse = HttpAgreementResponse(messageInfo.response, cache)
        }

        if (rule.command.isEmpty()) return Pair(false, emptyMap())
        cmd[0] = rule.command

        BurpExtender.stdout.println("脚本: ${rule.name} 执行")
        return Pair(true, rule.args)
    }

    private fun removeDefaultPort(url: String): String {
        return when {
            url.startsWith("http://") && url.contains(":80/") -> url.replace(":80", "")
            url.startsWith("https://") && url.contains(":443/") -> url.replace(":443", "")
            else -> url
        }
    }

    private fun processMessage(
        cache: Cache,
        cmd: String,
        args: Map<String, String>,
        commandType: CommandType,
        updateMessage: (ByteArray) -> Unit
    ) {
        if (Execution.run(cmd, commandType, cache.temp, args)) {
            if (commandType == CommandType.RequestToServer || commandType == CommandType.RequestFromClient) {
                updateMessage(httpAgreementRequest?.toRequest(cache) ?: byteArrayOf())
            }else{
                updateMessage(httpAgreementResponse?.toResponse(cache) ?: byteArrayOf())
            }
        }
    }

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        val cmd = arrayOfNulls<String>(1)
        val cache = Cache()
        try {
            val (shouldIntercept, args) = analyze(messageInfo, messageIsRequest, cmd, cache)
            if (!shouldIntercept) {
                cache.destroy()
                return
            }

            BurpExtender.stdout.println("=================================================")
            val commandType = if (messageIsRequest) {
                BurpExtender.stdout.println("======> burp发出到服务器")
                CommandType.RequestToServer
            } else {
                BurpExtender.stdout.println("======> 服务端返回到burp")
                CommandType.ResponseFromServer
            }
            val updateMessage = if (messageIsRequest) { messageInfo::setRequest } else { messageInfo::setResponse }

            processMessage(cache, cmd[0]!!, args, commandType, updateMessage)
        } catch (e: IOException) {
            BurpExtender.stderr.println("错误信息：" + e.message)
        }
    }

    override fun processProxyMessage(messageIsRequest: Boolean, message: IInterceptedProxyMessage) {
        val cmd = arrayOfNulls<String>(1)
        val cache = Cache()
        try {
            val (shouldIntercept, args) = analyze(message.messageInfo, messageIsRequest, cmd, cache)
            if (!shouldIntercept) {
                cache.destroy()
                return
            }

            BurpExtender.stdout.println("=================================================")
            val commandType = if (messageIsRequest) {
                BurpExtender.stdout.println("======> 客户端发出到burp")
                CommandType.RequestFromClient
            } else {
                BurpExtender.stdout.println("======> burp返回到客户端")
                CommandType.ResponseToClient
            }
            val updateMessage = if (messageIsRequest) { message.messageInfo::setRequest } else { message.messageInfo::setResponse }

            processMessage(cache, cmd[0]!!, args, commandType, updateMessage)
        } catch (e: IOException) {
            BurpExtender.stdout.println("错误信息：" + e.message)
        }
    }
}