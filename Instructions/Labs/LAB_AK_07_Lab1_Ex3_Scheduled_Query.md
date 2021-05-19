# 模块 7 - 实验室 1 - 练习 3 - 创建计划查询

### 任务 1：创建计划查询。

在此任务中，你将创建一个计划查询。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 在 **“登录”** 对话框中，复制粘贴实验室托管提供者提供的**租户电子邮件**帐户，然后选择 **“下一步”**。

3. 在 **“输入密码”** 对话框中，复制粘贴实验室托管提供者提供的**租户密码**，然后选择 **“登录”**。

4. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择 **“Azure Sentinel”**。

5. 选择 Azure Sentinel 工作区。

6. 从“配置”区域选择 **“分析”**。

7. 选择 **“创建”** 按钮，然后选择 **“计划查询规则”**。

8. 在“常规”选项卡上，输入名称 *“不活跃帐户注册尝试”*。

9. 对于“策略”，选择 **“初始访问”**。

10. 对于“严重性”，选择 **“中”**

11. 选择 **“下一步: 设置规则逻辑 >”** 按钮：

12. 对于规则查询，粘贴以下 KQL 语句：

SigninLogs
| where ResultType == "50057"
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator."
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count(), applicationCount = dcount(AppDisplayName), 
applicationSet = makeset(AppDisplayName) by UserPrincipalName, IPAddress
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress

**警告：** 对虚拟机使用粘贴功能时。  可能添加额外的 | （竖线）字符。  确保粘贴的内容类似以下 KQL 语句。

**备注:** 如果选择“查看查询结果”的链接，应该不会接收到任何结果。  你应该也不会收到错误。  

13. 查看“映射”条目。  实体在查询中显示为已映射，因为查询输出包括以下字段：

timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress

14. 回到“查询计划”区域的“分析规则向导 - 创建新规则”边栏选项卡，为“运行查询间隔”选项输入 **“5”** 并选择 **“分钟”**。

15. 在“查询计划”区域，对于“查询过去这段时间的数据”选项输入 **“1”** 并选择 **“天”**。

16. 对于“警报阈值”区域，不更改任何选项。

**备注:** 最佳做法是在 KQL 查询语句中管理阈值。

17. 对于“事件分组”区域，保持选中 **“将所有事件分组到一个警报中”**。

18. 选择 **“下一步: 事件设置”** 按钮。  

19. 在“事件设置”选项卡上，查看默认选项。

20. 选择 **“下一步: 自动响应”** 按钮。

21. 在“自动响应”选项卡上，选择你之前创建的 playbook Post-Message-Teams。

22. 选择 **“下一步: 查看”** 按钮。
  
23. 选择 **“创建”**。

### 任务 2：测试我们的新规则。

在此任务中，你将创建“测试新计划查询”规则。

1. 在 Azure 门户的搜索栏中，选择 *“Azure Active Directory”*。然后选择 **“Azure Active Directory”**。

2. 在“管理”区域中选择 **“用户”**。

3. 在列表中选择用户 **“Christie Cline”**。将会显示 Christie Cline | 个人资料页。

4. 选择 **“编辑”**。

5. 在“设置”区域，将 **“阻止登录”** 更改为 **“是”**。

6. 现在从命令栏选择 **“保存”**。

7. 在 Azure 门户中，选择右上角的用户头像并注销。

8. 关闭浏览器。

9. 打开浏览器并导航到 https://portal.office.com， 然后尝试使用用户 ChristieC@**租户电子邮件域**登录，密码应与管理员的租户密码相同。  你应接收到警告称将会锁定帐户。

10. 关闭浏览器。等待 10 分钟以便警报处理。

11.  在 Microsoft Edge 浏览器中，转到 Azure 门户 (https://portal.azure.com)

12. 在 **“登录”** 对话框中，复制粘贴实验室托管提供者为管理员用户提供的**租户电子邮件**帐户，然后选择 **“下一步”**。

13. 在 **“输入密码”** 对话框中，复制粘贴实验室托管提供者为管理员用户提供的**租户密码**，然后选择 **“登录”**。

14. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择 **“Azure Sentinel”**。

15. 选择 Azure Sentinel 工作区。

16. 选择 **“事件”** 菜单选项。

17. 应该会看到新创建的事件。  选择“事件”并查看右侧边栏选项卡中的信息。

18. 打开 Microsoft Teams。转到你的 *SOC* 团队，并查看关于事件的消息帖子。

## 转到练习 4