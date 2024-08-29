package net.ankio.icrypto.rule

import net.ankio.icrypto.BurpExtender
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

object Execution {

    fun run(command: String, type: CommandType?, file: String?, args: Map<String, String>): Boolean {
        val commandList = mutableListOf<String>()
        val normalizedCommand = normalizeCommand(command)

        // 将基础命令添加到列表中
        commandList.add(normalizedCommand.first())

        // 如果有多个命令部分，将其余部分添加为参数
        if (normalizedCommand.size > 1) {
            commandList.addAll(normalizedCommand.subList(1, normalizedCommand.size))
        }

        // 遍历 args 参数并添加到命令列表中
        args.forEach { (key, value) ->
            commandList.add("--$key")
            commandList.add(value)
        }

        // 根据 CommandType 添加 --operationType 参数
        val dataType = when (type) {
            CommandType.RequestFromClient -> "0"
            CommandType.RequestToServer -> "1"
            CommandType.ResponseToClient -> "3"
            else -> "2"
        }
        commandList.add("--operationType")
        commandList.add(dataType)

        // 添加 --dataDir 参数
        if (file != null) {
            commandList.add("--dataDir")
            commandList.add(file)
        }

        // 执行命令并返回结果
        val result: String = exec(commandList).trim()
        return "success" == result
    }

    // 规范化命令，根据操作系统处理路径和参数
    private fun normalizeCommand(command: String): List<String> {
        val parts = command.split(" ").toMutableList() // 转换为可变列表
        val osName = System.getProperty("os.name").lowercase()

        val executable = File(parts[0])

        // 处理 Windows 路径
        if (osName.contains("win")) {
            if (executable.isAbsolute) {
                parts[0] = executable.canonicalPath.replace("/", "\\")
            }
        } else {
            // 处理非 Windows 系统路径
            if (executable.isAbsolute) {
                parts[0] = executable.canonicalPath
            }
        }

        return parts
    }

    private fun exec(commandList: List<String>): String {
        try {
            BurpExtender.stdout.println("执行命令：${commandList.joinToString(" ")}")
            val processBuilder = ProcessBuilder(commandList)

            val process = processBuilder.start()

            val inputStream = process.inputStream
            val reader = BufferedReader(InputStreamReader(inputStream))

            val errorStream = process.errorStream
            val errorReader = BufferedReader(InputStreamReader(errorStream))

            val errOutput = StringBuilder()
            var errLine: String?
            while (errorReader.readLine().also { errLine = it } != null) {
                errOutput.append(errLine).append("\n")
            }
            errorReader.close()
            if (errOutput.isNotEmpty()) {
                BurpExtender.stderr.println("执行错误：$errOutput")
            }

            val output = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                output.append(line).append("\n")
            }
            if (output.isEmpty()) {
                BurpExtender.stderr.println("执行错误：输出内容为空")
            }

            val exitCode = process.waitFor()
            BurpExtender.stdout.println("执行结束：$exitCode")

            reader.close()
            process.destroy()

            return output.toString()
        } catch (e: Exception) {
            e.printStackTrace()
            BurpExtender.stderr.println("执行异常：${e.message}")
            return e.message ?: ""
        }
    }
}