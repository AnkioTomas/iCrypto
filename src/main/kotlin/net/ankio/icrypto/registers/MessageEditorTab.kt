package net.ankio.icrypto.registers

import burp.IMessageEditorController
import burp.IMessageEditorTab
import net.ankio.icrypto.BurpExtender
import net.ankio.icrypto.http.Cache
import net.ankio.icrypto.http.HttpAgreementRequest
import net.ankio.icrypto.http.HttpAgreementResponse
import net.ankio.icrypto.rule.CommandType
import net.ankio.icrypto.rule.Execution
import net.ankio.icrypto.rule.Rule
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import javax.swing.*
import javax.swing.event.ListDataListener

class MessageEditorTab internal constructor(private val iMessageEditorController: IMessageEditorController?) :
    IMessageEditorTab {
    private val messageArea: JTextArea = JTextArea().apply {
        isEditable = true
        lineWrap = true
        wrapStyleWord = true
    }
    private var isRequest = false
    private val cache = Cache()
    private var originalContent: ByteArray? = null
    private var showError: Boolean = false
    private var httpAgreementRequest: HttpAgreementRequest? = null
    private var httpAgreementResponse: HttpAgreementResponse? = null
    private val selectBox: JComboBox<Rule> = JComboBox<Rule>().apply {
        addActionListener { selectItem() }
        preferredSize = Dimension(0, 30)
    }
    private val rootPanel: JSplitPane = JSplitPane()

    init {
        val label1 = JLabel("请选择脚本").apply {
            text = "请选择脚本  "
        }

        val infoPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JLabel("选择脚本执行后，请回到Raw或Pretty选项卡中修改内容.").apply {
                foreground = Color.ORANGE
            })
        }

        val panel1 = JPanel().apply {
            preferredSize = Dimension(0, 30)
            maximumSize = Dimension(Int.MAX_VALUE, 30)
            layout = BorderLayout()
            add(label1, BorderLayout.WEST)
//            add(infoPanel, BorderLayout.SOUTH)
            add(selectBox, BorderLayout.CENTER)
        }

        val editorScrollPane = JScrollPane(messageArea)

        rootPanel.apply {
            orientation = JSplitPane.VERTICAL_SPLIT
            topComponent = panel1
            bottomComponent = editorScrollPane
        }

        selectBox.model = RuleModel()
    }

    private fun selectItem() {
        val rule = selectBox.selectedItem as Rule
        if (rule.command.isEmpty()) return

        // 从 originalContent 初始化请求和响应对象
        httpAgreementRequest = originalContent?.let { HttpAgreementRequest(it, cache) }
        httpAgreementResponse = originalContent?.let { HttpAgreementResponse(it, cache) }

        processRule(rule)
    }

    private fun processRule(rule: Rule) {
        val commandType = getCommandType(rule)
        if (Execution.run(rule.command, commandType, cache.temp, rule.args)) {
            updateMessageArea()
        } else {
            showError("加解密失败，详情请看日志")
        }
    }

    private fun updateMessageArea() {
        val message = if (isRequest) httpAgreementRequest?.toRequest(cache) ?: ByteArray(0)
        else httpAgreementResponse?.toResponse(cache) ?: ByteArray(0)
        setMessage(message, isRequest)
    }

    private fun showError(message: String) {
        showError = true
        setMessage(message.toByteArray(), isRequest)
    }

    private fun getCommandType(rule: Rule): CommandType {
        return if (rule.name.contains("（收到请求/响应）")) {
            if (isRequest) CommandType.RequestFromClient else CommandType.ResponseFromServer
        } else {
            if (isRequest) CommandType.RequestToServer else CommandType.ResponseToClient
        }
    }

    override fun getTabCaption(): String = BurpExtender.extensionName

    override fun getUiComponent(): Component = rootPanel

    override fun isEnabled(content: ByteArray, isRequest: Boolean): Boolean = true

    override fun setMessage(content: ByteArray, isRequest: Boolean) {
        this.isRequest = isRequest

        // 当没有错误时，保存原始内容
        if (!showError) {
            originalContent = content
        }

        // 根据是否显示错误更新 messageArea 的内容
        messageArea.text = if (showError) {
            String(content) // 如果有错误，使用当前传入的content显示错误信息
        } else {
            String(originalContent!!) // 否则显示原始内容
        }

        showError = false // 重置错误状态，准备下一次使用
    }

    override fun getMessage(): ByteArray = originalContent ?: ByteArray(0)

    override fun isModified(): Boolean = true

    override fun getSelectedData(): ByteArray = messageArea.selectedText?.toByteArray() ?: ByteArray(0)

    private class RuleModel : ComboBoxModel<Rule> {
        private val rules: ArrayList<Rule> = ArrayList(BurpExtender.config.list.flatMap { rule ->
            listOf(rule.copy().apply { name += "（收到请求/响应）" }, rule.copy().apply { name += "（发出请求/响应）" })
        })
        private var selectedRule: Rule? = null

        override fun getSize(): Int = rules.size

        override fun getElementAt(index: Int): Rule = rules[index]

        override fun addListDataListener(l: ListDataListener) {}

        override fun removeListDataListener(l: ListDataListener) {}

        override fun setSelectedItem(item: Any?) {
            selectedRule = item as? Rule
        }

        override fun getSelectedItem(): Rule? = selectedRule
    }
}