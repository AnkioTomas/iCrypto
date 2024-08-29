/*
 * Created by JFormDesigner on Mon Sep 19 12:24:48 CST 2022
 */

package net.ankio.icrypto.ui;
import net.ankio.icrypto.BurpExtender;
import net.ankio.icrypto.rule.Rule;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ListSelectionEvent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


/**
 * 插件的GUI实现
 * @author ankio
 */
public class MainGUI  {

    private final Map<JPanel, JTextField[]> argPanels = new HashMap<>();

    /**
     * 构造函数
     */ public MainGUI() {
        //初始化UI
        initComponents();
        //初始化数据
        initData();
    }


    public void initData(){
        // list填充
        autoRun.setSelected(BurpExtender.config.getAuto());
        ArrayList<String> arrayList = new ArrayList<>();
        for (Rule rule : BurpExtender.config.getList()) {
            arrayList.add(rule.getName());
        }
        watchList.setListData(arrayList.toArray(new String[0]));
        initTable();
    }

    private void initTable(){
        watchName.setText("");
        watchCustom.setText("");
        watchUrlInclude.setText("");
        panel5.removeAll();  // 清空 panel5 中的内容
        argPanels.clear();   // 清空 argPanels Map

        if (select != -1) {
            Rule rule = BurpExtender.config.getList().get(select);
            if (rule != null) {
                watchName.setText(rule.getName());
                watchCustom.setText(rule.getCommand());
                watchUrlInclude.setText(rule.getUrl());

                // 添加 args 参数
                for (Map.Entry<String, String> entry : rule.getArgs().entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();
                    JPanel argPanel = createArgPanel(key, value);  // 创建带有初始值的 argPanel
                    panel5.add(argPanel);
                }

                panel5.revalidate();
                panel5.repaint();
            }
        }
    }

    private int select = -1;

    /**
     * 显示错误信息
     */
    private void showMsg(String msg){
        JOptionPane.showMessageDialog(null, msg, "错误",
                JOptionPane.ERROR_MESSAGE);
    }
    private void watchSave(ActionEvent e) {

        if(watchName.getText().isEmpty()){
            showMsg("必须填写脚本名称");
            return;
        }
        if(watchCustom.getText().isEmpty()){
            showMsg("必须填写脚本执行命令");
            return;
        }

        Map<String, String> args = new HashMap<>();
        for (Map.Entry<JPanel, JTextField[]> entry : argPanels.entrySet()) {
            JTextField[] fields = entry.getValue();
            String key = fields[0].getText();
            String value = fields[1].getText();

            // 检查重复的 key
            if (args.containsKey(key)) {
                showMsg("参数重复: " + key);
                return;
            }

            if (!key.isEmpty()) {
                args.put(key, value);
            }
        }

        Rule rule = new Rule(watchName.getText(), watchUrlInclude.getText(), watchCustom.getText(), args);
        BurpExtender.config.add(rule);
        initData();
    }

    private void watchDel(ActionEvent e) {
        if(select!=-1){
            BurpExtender.config.del(select);
            select = -1;
            initData();
        }
    }

    /**
     * 获取根View
     */
    public JPanel getRoot(){
        return panel1;
    }

    private void autoRunStateChanged(ChangeEvent e) {
        BurpExtender.config.setAuto(autoRun.isSelected());
    }

    private void watchListValueChanged(ListSelectionEvent e) {
        select = watchList.getSelectedIndex();
        if (select == -1) return;

        Rule rule = BurpExtender.config.getList().get(select);
        if(rule==null)return;
        initTable();
        watchName.setText(rule.getName());
        watchCustom.setText(rule.getCommand());
        watchUrlInclude.setText(rule.getUrl());
    }

    private JPanel createArgPanel(String key, String value) {
        JPanel newPanel = new JPanel();

        newPanel.setFont(new Font("Noto Sans", Font.PLAIN, 20));
        newPanel.setMaximumSize(new Dimension(32767, 50));
        newPanel.setRequestFocusEnabled(false);
        newPanel.setLayout(new FlowLayout(FlowLayout.LEFT));

        //---- newLabel1 ----
        JLabel newLabel1 = new JLabel("\u53c2\u6570\uff1a");
        newLabel1.setHorizontalAlignment(SwingConstants.LEFT);
        newPanel.add(newLabel1);

        //---- newTextField1 ----
        PlaceholderTextField newTextField1 = new PlaceholderTextField("name tips: initToke");
        newTextField1.setText(key != null ? key : "");
        newTextField1.setColumns(10);
        newPanel.add(newTextField1);

        //---- newLabel2 ----
        JLabel newLabel2 = new JLabel(":");
        newLabel2.setFont(new Font("Noto Sans", Font.PLAIN, 20));
        newLabel2.setHorizontalAlignment(SwingConstants.CENTER);
        newPanel.add(newLabel2);

        //---- newTextField2 ----
        PlaceholderTextField newTextField2 = new PlaceholderTextField("value tips: 30dd2c141cae45ca8091d8a5d5ba217f");
        newTextField2.setText(value != null ? value : "");
        newTextField2.setColumns(30);
        newTextField2.setHorizontalAlignment(SwingConstants.LEFT);
        newPanel.add(newTextField2);

        //---- button2 ----
        JButton newButton = new JButton("-");
        newButton.setPreferredSize(new Dimension(35, 35));
        newButton.setMaximumSize(new Dimension(35, 35));
        newButton.setMinimumSize(new Dimension(35, 35));
        newButton.addActionListener(e -> {
            JButton sourceButton = (JButton) e.getSource();
            JPanel panel = (JPanel) sourceButton.getParent();
            delCmdArgs(panel);
        });
        newPanel.add(newButton);

        // 保存到 map 中
        argPanels.put(newPanel, new JTextField[]{newTextField1, newTextField2});

        return newPanel;
    }

    private void addCmdArgs(ActionEvent e) {
        JPanel newPanel = createArgPanel(null, null);  // 创建不带初始值的 argPanel
        panel5.add(newPanel);  // 添加到某个容器面板中
        panel5.revalidate();  // 重新布局
        panel5.repaint();  // 重新绘制
    }

    private void delCmdArgs(JPanel panel) {
        argPanels.remove(panel);  // 从 map 中移除
        panel.getParent().remove(panel);  // 从 UI 中移除
        panel.getParent().revalidate();  // 重新布局
        panel.getParent().repaint();  // 重新绘制
    }

    // 新增脚本方法
    private void addNewScript(ActionEvent e) {
        // 生成一个唯一的脚本名称
        String baseName = "新脚本-";
        String randomString = generateRandomString(6); // 生成6位随机字符串
        String newName = baseName + randomString;

        // 创建新的脚本
        watchName.setText(newName);
        watchCustom.setText("");
        watchUrlInclude.setText("");
        panel5.removeAll();
        argPanels.clear();
        panel5.revalidate();
        panel5.repaint();

        // 将新脚本添加到配置中
        Rule newRule = new Rule(newName, "", "", new HashMap<>());
        BurpExtender.config.add(newRule);
        initData();
        watchList.setSelectedIndex(watchList.getModel().getSize() - 1);
    }

    // 生成随机字符串的方法
    private String generateRandomString(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            sb.append(characters.charAt(random.nextInt(characters.length())));
        }

        return sb.toString();
    }

    // 刷新脚本信息方法
    private void refreshScripInfo(ActionEvent e) {
        initData();  // 重新加载所有数据并刷新界面
    }






    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        panel1 = new JPanel();
        panel7 = new JPanel();
        button2 = new JButton();
        button3 = new JButton();
        splitPane1 = new JSplitPane();
        watchList = new JList<>();
        panel2 = new JPanel();
        panel3 = new JPanel();
        watchUrlInclude = new JTextField();
        label2 = new JLabel();
        autoRun = new JCheckBox();
        panel4 = new JPanel();
        watchCustom = new JTextField();
        label8 = new JLabel();
        label7 = new JLabel();
        watchName = new JTextField();
        scrollPane1 = new JScrollPane();
        panel5 = new JPanel();
        button1 = new JButton();
        watchSave = new JButton();
        watchDel = new JButton();
        label1 = new JLabel();

        //======== panel1 ========
        {
            panel1.setLayout(new BorderLayout());

            //======== panel7 ========
            {
                panel7.setBorder(new TitledBorder("\u63d2\u4ef6\u914d\u7f6e"));
                panel7.setPreferredSize(new Dimension(1040, 70));

                //---- button2 ----
                button2.setText("\u65b0\u589e\u811a\u672c");
                button2.addActionListener(e -> addNewScript(e));

                //---- button3 ----
                button3.setText("\u5237\u65b0\u811a\u672c");
                button3.addActionListener(e -> refreshScripInfo(e));

                GroupLayout panel7Layout = new GroupLayout(panel7);
                panel7.setLayout(panel7Layout);
                panel7Layout.setHorizontalGroup(
                    panel7Layout.createParallelGroup()
                        .addGroup(panel7Layout.createSequentialGroup()
                            .addGap(22, 22, 22)
                            .addComponent(button2)
                            .addGap(40, 40, 40)
                            .addComponent(button3)
                            .addContainerGap(778, Short.MAX_VALUE))
                );
                panel7Layout.setVerticalGroup(
                    panel7Layout.createParallelGroup()
                        .addGroup(panel7Layout.createSequentialGroup()
                            .addContainerGap()
                            .addGroup(panel7Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(button2)
                                .addComponent(button3))
                            .addContainerGap(18, Short.MAX_VALUE))
                );
            }
            panel1.add(panel7, BorderLayout.NORTH);

            //======== splitPane1 ========
            {
                splitPane1.setDividerLocation(200);

                //---- watchList ----
                watchList.setMaximumSize(new Dimension(200, 62));
                watchList.setFixedCellWidth(200);
                watchList.setBorder(LineBorder.createBlackLineBorder());
                watchList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                watchList.addListSelectionListener(e -> watchListValueChanged(e));
                splitPane1.setLeftComponent(watchList);

                //======== panel2 ========
                {
                    panel2.setBorder(new EmptyBorder(20, 20, 20, 20));

                    //======== panel3 ========
                    {
                        panel3.setBorder(new TitledBorder("\u76d1\u63a7\u53c2\u6570\uff08\u81ea\u52a8\u6267\u884c\u811a\u672c\u9700\u8981\u914d\u7f6e\uff09"));

                        //---- label2 ----
                        label2.setText("URL\u5305\u542b:");

                        //---- autoRun ----
                        autoRun.setText("\u81ea\u52a8\u6267\u884c\u811a\u672c");
                        autoRun.addChangeListener(e -> autoRunStateChanged(e));

                        GroupLayout panel3Layout = new GroupLayout(panel3);
                        panel3.setLayout(panel3Layout);
                        panel3Layout.setHorizontalGroup(
                            panel3Layout.createParallelGroup()
                                .addGroup(panel3Layout.createSequentialGroup()
                                    .addContainerGap()
                                    .addGroup(panel3Layout.createParallelGroup()
                                        .addComponent(autoRun, GroupLayout.PREFERRED_SIZE, 136, GroupLayout.PREFERRED_SIZE)
                                        .addGroup(panel3Layout.createSequentialGroup()
                                            .addComponent(label2, GroupLayout.PREFERRED_SIZE, 70, GroupLayout.PREFERRED_SIZE)
                                            .addGap(18, 18, 18)
                                            .addComponent(watchUrlInclude, GroupLayout.DEFAULT_SIZE, 673, Short.MAX_VALUE)))
                                    .addGap(0, 0, 0))
                        );
                        panel3Layout.setVerticalGroup(
                            panel3Layout.createParallelGroup()
                                .addGroup(panel3Layout.createSequentialGroup()
                                    .addContainerGap()
                                    .addGroup(panel3Layout.createParallelGroup()
                                        .addComponent(label2, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(watchUrlInclude, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                    .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(autoRun)
                                    .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        );
                    }

                    //======== panel4 ========
                    {
                        panel4.setBorder(new TitledBorder("\u811a\u672c\u914d\u7f6e"));

                        //---- label8 ----
                        label8.setText("\u6267\u884c\u547d\u4ee4\uff08\u53ef\u6267\u884c\u7a0b\u5e8f\u5b8c\u6574\u8def\u5f84\uff09\uff1a");

                        //---- label7 ----
                        label7.setText("\u914d\u7f6e\u540d\u79f0\uff1a");

                        //======== scrollPane1 ========
                        {

                            //======== panel5 ========
                            {
                                panel5.setBorder(new TitledBorder("\u5176\u4ed6\u547d\u4ee4\u53c2\u6570"));
                                panel5.setLayout(new BoxLayout(panel5, BoxLayout.Y_AXIS));
                            }
                            scrollPane1.setViewportView(panel5);
                        }

                        //---- button1 ----
                        button1.setFont(new Font("Noto Sans", Font.BOLD, 30));
                        button1.setText("+");
                        button1.addActionListener(e -> addCmdArgs(e));

                        GroupLayout panel4Layout = new GroupLayout(panel4);
                        panel4.setLayout(panel4Layout);
                        panel4Layout.setHorizontalGroup(
                            panel4Layout.createParallelGroup()
                                .addGroup(panel4Layout.createSequentialGroup()
                                    .addContainerGap()
                                    .addGroup(panel4Layout.createParallelGroup()
                                        .addGroup(panel4Layout.createSequentialGroup()
                                            .addComponent(label8)
                                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                            .addComponent(watchCustom, GroupLayout.DEFAULT_SIZE, 541, Short.MAX_VALUE))
                                        .addGroup(panel4Layout.createSequentialGroup()
                                            .addComponent(label7)
                                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                            .addComponent(watchName))
                                        .addGroup(panel4Layout.createSequentialGroup()
                                            .addComponent(scrollPane1)
                                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                            .addComponent(button1, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)))
                                    .addContainerGap())
                        );
                        panel4Layout.setVerticalGroup(
                            panel4Layout.createParallelGroup()
                                .addGroup(panel4Layout.createSequentialGroup()
                                    .addGap(8, 8, 8)
                                    .addGroup(panel4Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(label7)
                                        .addComponent(watchName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                    .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                    .addGroup(panel4Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(label8)
                                        .addComponent(watchCustom, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                    .addGroup(panel4Layout.createParallelGroup()
                                        .addGroup(panel4Layout.createSequentialGroup()
                                            .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                            .addComponent(scrollPane1, GroupLayout.DEFAULT_SIZE, 160, Short.MAX_VALUE))
                                        .addGroup(panel4Layout.createSequentialGroup()
                                            .addGap(53, 53, 53)
                                            .addComponent(button1, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
                                            .addGap(0, 68, Short.MAX_VALUE))))
                        );
                    }

                    //---- watchSave ----
                    watchSave.setText("\u4fdd\u5b58");
                    watchSave.addActionListener(e -> watchSave(e));

                    //---- watchDel ----
                    watchDel.setText("\u5220\u9664");
                    watchDel.addActionListener(e -> watchDel(e));

                    GroupLayout panel2Layout = new GroupLayout(panel2);
                    panel2.setLayout(panel2Layout);
                    panel2Layout.setHorizontalGroup(
                        panel2Layout.createParallelGroup()
                            .addGroup(panel2Layout.createSequentialGroup()
                                .addGroup(panel2Layout.createParallelGroup()
                                    .addComponent(panel4, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addGroup(panel2Layout.createSequentialGroup()
                                        .addContainerGap()
                                        .addComponent(watchDel)
                                        .addGap(18, 18, 18)
                                        .addComponent(watchSave)
                                        .addGap(0, 615, Short.MAX_VALUE))
                                    .addComponent(panel3, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addContainerGap())
                    );
                    panel2Layout.setVerticalGroup(
                        panel2Layout.createParallelGroup()
                            .addGroup(panel2Layout.createSequentialGroup()
                                .addComponent(panel4, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(panel3, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addGroup(panel2Layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                    .addComponent(watchDel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(watchSave, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGap(0, 0, Short.MAX_VALUE))
                    );
                }
                splitPane1.setRightComponent(panel2);
            }
            panel1.add(splitPane1, BorderLayout.CENTER);
        }

        //---- label1 ----
        label1.setText("    \u795e\u8bf4\uff1a\u8981\u89e3\u5bc6\uff0c\u4e8e\u662f\u5c31\u6709\u4e86iCrypto\u3002Powered by Ankio");
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }


    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    private JPanel panel1;
    private JPanel panel7;
    private JButton button2;
    private JButton button3;
    private JSplitPane splitPane1;
    private JList<String> watchList;
    private JPanel panel2;
    private JPanel panel3;
    private JTextField watchUrlInclude;
    private JLabel label2;
    private JCheckBox autoRun;
    private JPanel panel4;
    private JTextField watchCustom;
    private JLabel label8;
    private JLabel label7;
    private JTextField watchName;
    private JScrollPane scrollPane1;
    private JPanel panel5;
    private JButton button1;
    private JButton watchSave;
    private JButton watchDel;
    private JLabel label1;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}