# 模块 7 - 实验室 1 - 练习 3 - 创建计划查询

### 任务 1：创建计划查询。

在此任务中，你将创建一个计划查询，并将其连接到在上一个练习中创建的 Teams 频道。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 在 **“登录”** 对话框中，复制粘贴实验室托管提供者提供的**租户电子**邮件帐户，然后选择 **“下一步”**。

3. 在 **“输入密码”** 对话框中，复制粘贴实验室托管提供者提供的**租户密码**，然后选择 **“登录”**。

4. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择 **“Azure Sentinel”**。

5. 选择 Azure Sentinel 工作区。

6. 从“配置”区域选择 **“分析”**。

7. 选择 **“+ 创建”** 按钮，然后选择 **“计划查询规则”**。

8. 在分析规则向导的“常规”选项卡上，输入名称 *“非活动帐户登录尝试”*。

9. 对于“策略”，选择 **“初始访问”**。

10. 对于“严重性”，选择 **“中等”**。

11. 选择 **“下一步: 设置规则逻辑 >”** 按钮：

12. 对于规则查询，粘贴以下 KQL 语句：

```KQL
SigninLogs
| where ResultType == "50057"
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator."
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), count(), applicationCount = dcount(AppDisplayName), 
applicationSet = makeset(AppDisplayName) by UserPrincipalName, IPAddress
| extend timestamp = StartTimeUtc, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
```

**警告：** 对虚拟机使用粘贴功能时。  可能添加额外的 | （竖线）字符。  确保粘贴的内容与上面的 KQL 语句类似。

**备注：** 如果选择“查看查询结果”的链接，应该不会接收到任何结果。  你应该也不会收到错误。  

13. 返回到“分析规则向导 - 创建新规则”边栏选项卡中，在“查询计划”区域的 *“运行查询的间隔时间”* 选项处输入 **“5”** 并选择 **“分钟”**。

14. 在“查询计划”区域的 *“查找过去某段时间的数据”* 处，输入 **“1”** 并选择 **“天”**。

15. 对于“警报阈值”区域，不更改任何选项。

**备注：** 最佳做法是在 KQL 查询语句中管理阈值。

16. 对于“事件分组”区域，保持选中 **“将所有事件分组到一个警报中”**。

17. 选择 **“下一步: 事件设置 >”** 按钮。  

18. 在“事件设置”选项卡上，查看默认选项。

19. 选择 **“下一步: 自动响应 >”** 按钮。

20. 在“自动响应”选项卡的“警报自动化”区域，选择在上一个练习中创建的 *“PostMessageTeams-OnAlert”* playbook。

22. 选择 **“下一步: 查看 >”** 按钮。
  
23. 选择 **“创建”**。

### 任务 2：测试我们的新规则。

在此任务中，你将测试新的计划查询规则。

1. 在 Azure 门户的搜索栏中，选择 *“Azure Active Directory”*。然后选择 **“Azure Active Directory”**。

2. 在“管理”区域中选择 **“用户”**。

3. 选择列表中的用户 **“Christie Cline”**，随即显示 Christie Cline 的 | 个人资料页。

4. 从命令栏中选择 **“编辑”**。

5. 在“设置”区域，将 **“阻止登录”** 更改为 **“是”**。

6. 现在从命令栏选择 **“保存”**。

7. 在 Azure 门户中，选择右上角的用户头像并注销。

8. 关闭浏览器。

9. 在 Microsoft Edge 中打开新的“In-Private 浏览”会话并导航到 https://portal.office.com，尝试使用用户帐户（ChristieC@ **租户电子邮件域** ）登录，而密码应与管理员的租户密码相同。  你应接收到帐户已锁定的警告。这在预料之中，该操作应会触发警报。

10. 关闭浏览器。最后一步触发的警报可能需要 10 分钟来处理。你可以继续进行下一个练习，稍后再返回到这里。

11. 在 Edge 浏览器中，转到 Azure 门户 (https://portal.azure.com)。

12. 在 **“登录”** 对话框中，复制粘贴实验室托管提供者为管理员用户提供的**租户电子**邮件帐户，然后选择 **“下一步”**。

13. 在 **“输入密码”** 对话框中，复制粘贴实验室托管提供者为管理员用户提供的**租户密码**，然后选择 **“登录”**。

14. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择 **“Azure Sentinel”**。

15. 选择 Azure Sentinel 工作区。

16. 选择 **“事件”** 菜单选项。

17. 应该会看到新创建的事件。  选择“事件”并查看右侧边栏选项卡中的信息。

18. 打开浏览器选项卡并转到 https://teams.microsoft.com，以打开 Microsoft Teams。转到 *SOC* 团队，查看发布的有关该事件的消息。

## 转到练习 4
