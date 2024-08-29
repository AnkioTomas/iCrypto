package net.ankio.icrypto.registers

import burp.IContextMenuFactory
import burp.IContextMenuInvocation
import net.ankio.icrypto.BurpExtender
import javax.swing.JMenu
import javax.swing.JMenuItem

class ContextMenuFactory : IContextMenuFactory {

    override fun createMenuItems(invocation: IContextMenuInvocation): List<JMenuItem>? {
        val menuItems = mutableListOf<JMenuItem>()

        val selectedMessages = invocation.selectedMessages
        val selectionBounds = invocation.selectionBounds

        if (selectedMessages != null && selectedMessages.isNotEmpty() && selectionBounds != null) {
            val selectedMessage = selectedMessages[0]
            val isRequest = invocation.invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
            val messageBytes: ByteArray = if (isRequest) {
                selectedMessage.request
            } else {
                selectedMessage.response
            }

            val selectedText: String? = if (selectionBounds[0] >= 0 && selectionBounds[1] > selectionBounds[0] && selectionBounds[1] <= messageBytes.size) {
                String(messageBytes, selectionBounds[0], selectionBounds[1] - selectionBounds[0])
            } else {
                null
            }

            // 如果没有选中文本，则返回空的菜单列表
            if (selectedText.isNullOrBlank()) {
                return menuItems
            }

            // 遍历所有 scripts
            for (rule in BurpExtender.config.list) {
                val scriptMenu = JMenu("Script: ${rule.name}")

                // 遍历 args 并生成菜单
                for (argKey in rule.args.keys) {
                    val argMenuItem = JMenuItem("set $argKey")

                    argMenuItem.addActionListener {
                        rule.args[argKey] = selectedText // 设置选中的文本到对应的 arg
                        BurpExtender.stdout.println("set ${rule.name} $argKey : $selectedText")

                        // 使用 update 方法更新并保存配置
                        BurpExtender.config.update(rule)
                    }

                    scriptMenu.add(argMenuItem)
                }

                menuItems.add(scriptMenu)
            }
        }

        return menuItems
    }
}