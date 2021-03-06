---
lab:
    title: '练习 2 - 使用 Microsoft Defender for Endpoint 缓解攻击'
    module: '模块 2 - 使用 Microsoft Defender for Endpoint 缓解威胁'
---

# 模块 2 - 实验室 1 - 练习 2 - 使用 Microsoft Defender for Endpoint 缓解攻击

## 实验室场景

你是一位安全运营分析师，你所在公司正在实现 Microsoft Defender for Endpoint。你的主管计划加入一些设备，以深入了解安全运营 (SecOps) 团队响应程序所需的更改。

为了探索 Defender for Endpoint 的攻击缓解功能，你将运行两次模拟攻击。


### 任务 1：模拟攻击

在此任务中，你将运行两次模拟攻击，以探索 Microsoft Defender for Endpoint 的功能。

1. 如果尚未在 Microsoft Edge 浏览器中访问 Microsoft 365 Defender 门户，请转到该门户 (https://security.microsoft.com) 并以租户管理员身份登录。

2. 从菜单中的“终结点”下，选择“**评估和教程**”，然后从左侧选择“**教程和模拟**”。

3. 选择“教程”选项卡，然后在“**自动调查(后门程序)**”下，单击“**阅读演练**”。这将打开一个新的浏览器标签页，其中有执行模拟的指令。

4. 在新的浏览器标签页中，找到名为“**运行模拟**”的部分，然后按照步骤运行攻击。这些步骤应包括：在“**教程**”选项卡的“**自动调查(后门)**”下，选择“**获取模拟文件**”来下载 **RS4_WinATP-Intro-Invoice.docm** 文件。继续按照浏览器标签页中的步骤运行攻击。

5. 在“**教程**”选项卡中，还请单击“**阅读演练**”，并按照文档的“**运行模拟**”部分来运行“**自动调查(无文件攻击)**”。

6. 在 Microsoft 365 Defender 门户中，从左侧菜单栏中选择“**事件和警报**”，然后选择“**事件**”。

7. 右侧窗格中将出现一个名为“多阶段事件...”的新事件。至少等待 5 分钟让事件出现。单击事件名称可加载其详细信息。

8. 单击“**管理事件**”，这将调出一个新的窗口边栏选项卡。此时在“事件标记”下键入“教程”，然后单击“**教程(新建)**”来创建一个新标记。单击“**分配给我**”开关，你会看到下面显示了你的帐户名称。在“分类”下，单击下拉菜单并选择“**实报**”。在“确定”下，单击下拉菜单并选择“**安全测试**”。根据需要添加任何注释，然后单击“**保存**”来完成操作。

9. 查看“警报”、“设备”、“用户”、“调查”、“证据和响应”、“图表”选项卡的内容。

>**警告：** 此处的模拟和教程非常适合实践式学习。  门户中会定期添加和修改模拟和教程。  但其中部分模拟和教程可能会影响为本培训课程设计的实验室的性能。  在使用 Azure 租户提供的课程时，请仅执行为本实验室提供的说明中推荐的模拟和教程。  使用此租户完成本培训课程后，可以参与其他模拟和租户教程。

## 你已完成本实验室。
