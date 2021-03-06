---
lab:
    title: '练习 1 - 探索 Microsoft 365 Defender'
    module: '模块 1 - 使用 Microsoft 365 Defender 缓解威胁'
---

# 模块 1 - 实验室 1 - 练习 1 - 探索 Microsoft 365 Defender 

## 实验室场景

你是一家公司的安全运营分析师，你所在公司正在实现 Microsoft 365 Defender。首先在 EOP 和 Microsoft Defender for Office 365 中分配预设安全策略。


### 任务 1：获取 Microsoft 365 凭据

启动实验室后，你将获得一个免费试用版租户，可在 Microsoft 虚拟实验室环境中访问。系统会自动向该租户分配一个唯一用户名和密码。你需要检索此用户名和密码，以便在 Microsoft 虚拟实验室环境中登录 Azure 和 Microsoft 365。 

由于学习合作伙伴可以通过多家授权实验室托管 (ALH) 提供商中的任何一家来提供本课程，因此检索与租户关联的租户 ID 所涉及的实际步骤可能因实验室托管提供商而异。因此，讲师需要向你提供必要的指导，介绍如何检索课程的此类信息。你应该记录以供稍后使用的信息包括：

- **租户后缀 ID。** 此 ID 适用于将在整个实验室中用于登录 Microsoft 365 的 onmicrosoft.com 帐户。其格式为 **{username}@ZZZZZZ.onmicrosoft.com**，其中 ZZZZZZ 是实验室托管提供者提供的唯一租户后缀 ID。记录此 ZZZZZZ 值以供稍后使用。当有任何实验室步骤指示你登录 Microsoft 365 门户时，都必须输入在此处获取的 ZZZZZZ 值。
- **租户密码。** 这是由实验室托管提供者提供的管理员帐户的密码。


### 任务 2：应用 Microsoft Defender for Office 365 预设安全策略

在此任务中，你将在 Microsoft 365 安全门户中分配 EOP 和 Microsoft Defender for Office 365 的预设安全策略。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 启动 Microsoft Edge 浏览器。

3. 在 Microsoft Edge 浏览器中，转到 Microsoft 365 Defender 门户 (https://security.microsoft.com)。

4. 在“**登录**”对话框中，复制并粘贴实验室托管提供者为管理员用户名提供的租户电子邮件帐户，然后选择“**下一步**”。

5. 在“**输入密码**”对话框中，复制粘贴实验室托管提供者提供的管理员的租户密码，然后选择“**登录**”。

    >**备注**：如果你收到消息“你无法访问此会话。”请等待 5 分钟，然后重试。有时访问规则需传播租户，这可能需要几分钟时间。  

6. 如果显示，请关闭 Microsoft 365 Defender 快速教程。

7. 在导航菜单的“**电子邮件和协作**”下，选择“**策略和规则**”。

8. 在“*策略和规则*”仪表板上，选择“**威胁策略**”。

9. 在“*策略*”仪表板上，选择“**预设安全策略**”。

10. 在“*标准保护*”下，选择“**编辑**”。

11. 在“*EOP 保护应用范围*”中，在“**域**”下写入租户的域名，将其选中并选择“**下一步**”。请注意，此配置将策略应用于反垃圾邮件、出站垃圾邮件过滤器、反恶意软件和反钓鱼网站。

12. 在“*Defender for Office 365 保护应用范围*”中，应用与上一步相同的配置，然后选择“**下一步**”。请注意，此配置将策略应用于反钓鱼网站、安全附件、安全链接。

13. 阅读“*查看并确认所做的更改*”下的内容，选择“**确认**”以应用更改，然后选择“**完成**”以完成操作。

14. 在“*严格保护*”下，选择“**编辑**”。

15. 在“*EOP 保护应用范围*”中，在“**组**”下写入“**领导层**”，将其选中并选择“**下一步**”。请注意，此配置将策略应用于反垃圾邮件、出站垃圾邮件过滤器、反恶意软件和反钓鱼网站。

16. 在“*Defender for Office 365 保护应用范围*”中，应用与上一步相同的配置，然后选择“**下一步**”。请注意，此配置将策略应用于反钓鱼网站、安全附件、安全链接。

17. 阅读“*查看并确认所做的更改*”下的内容，选择“**确认**”以应用更改，然后选择“**完成**”以完成操作。

18. 在顶部的中间菜单中，选择“**威胁策略**”以返回，然后在“*策略*”下选择“**安全附件**”。请注意，两个预设策略都在此处显示，且状态为“启用”。

19. 在菜单中选择“**全局设置**”。

20. 浏览可用选项，选择“**为 SharePoint、OneDrive 和 Microsoft Teams 启用 Defender for Office 365**”下的切换按钮，然后选择“**保存**”。

## 你已完成本实验室。
