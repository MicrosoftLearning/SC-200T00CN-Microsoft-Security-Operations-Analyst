﻿# 模块 6 - 实验室 1 - 练习 2 - 使用数据连接器将 Windows 设备连接到 Azure Sentinel

### 任务 1： 在 Azure 中创建 Windows 虚拟机。

在此任务中，你将创建一个 Windows 虚拟网络。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 在 Microsoft Edge 浏览器中，通过 https://portal.azure.com 导航到 Azure 门户。

3. 在 **“登录”** 对话框中，复制粘贴实验室托管提供者提供的**租户电子邮件**帐户，然后选择 **“下一步”**。

4. 在 **“输入密码”** 对话框中，复制粘贴实验室托管提供者提供的**租户密码**，然后选择 **“登录”**。

5. 选择 **“创建资源”**。

6. 在 **“在市场中搜索”** 框中，输入 *“Windows 10”*。 

7. 为 Microsoft Windows 10 选择 **“创建”** 下拉列表。  然后选择 **“Windows 10 企业版，版本 20H2”**。

8. 选择你的订阅。

9. 如果尚未创建新的资源组，请创建名为 **rg-AZWIN01** 的新资源组。

**备注:** 这需要是新的资源组。  你将在练习后删除虚拟机。  

10. 将虚拟机名称设置为 AZWIN01。

11. 将“区域”设置为你的地区的相应区域。  相应区域可以默认。

12. 输入你选择的 Azure 可接受的用户名。

13. 输入你选择的密码。 

**提示：** 使用你的租户密码可能最简单。

14. 选择“许可确认”。

15. 选择 **“查看 + 创建”**。

16. 选择 **“创建”**。等待创建资源，这可能需要几分钟的时间。

### 任务 2：连接 Azure Windows VM。

在此任务中，你要将 Azure Windows 虚拟机连接到 Azure Sentinel。

1. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择 **“Azure Sentinel”**。

2. 选择之前创建的 Azure Sentinel 工作区。

3. 从“数据连接器”选项卡，从列表中选择 **“安全事件”** 连接器。

4. 如果出现提示，选择 Azure Sentinel 工作区。

5. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

**备注:** 在 Windows 虚拟机上安装代理和在非 Azure Windows 计算机上安装代理的说明可能相反。  即使显示的文字相反，链接也可指向适当的位置。

6. 选择 **“在 Windows 虚拟机上安装代理”** 选项。

7. 选择 **“为 Azure Windows 虚拟机下载和安装代理”**。

8. 从你刚才在上一步中创建的列表中选择 **“AZWIN01”** 虚拟机，然后选择 **“连接”**。等到连接消息出现。

9. 在导航列表中选择 **“虚拟机”**。现在应能看到虚拟机已连接。

**备注:** 虚拟机仅在此任务中使用。  

10. 在 Azure 门户搜索中，输入 *“资源组”*。  选择 **“资源组”**。

11. 从列表中选择 **“rg-AZWIN01”**。

12. 从命令栏中选择 **“删除资源组”**。

13. 在“确定要删除吗”窗格中输入 **“rg-AZWIN01”**，然后选择 **“删除”**。

### 任务 3：连接非 Azure Windows 计算机。

在此任务中，你要将非 Azure Windows 虚拟机连接到 Azure Sentinel。

1. 以管理员身份使用密码登录到 WIN2 虚拟机：**Pa55w.rd**。  

2. 打开浏览器，搜索、下载并安装新的 Microsoft Edge 浏览器。启动新的 Microsoft Edge 浏览器。

3. 打开浏览器并使用你的凭据登录到 Azure 门户 (https://portal.azure.com)

4. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择 **“Azure Sentinel”**。

5. 选择 Azure Sentinel 工作区。

6. 从“数据连接器”选项卡，从列表中选择 **“安全事件”** 连接器。

7. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

8. 在“选择要流式传输的事件”区域，选择 **“所有事件”**，然后选择 **“应用更改”**。

9. 选择 **“在非 Azure Windows 虚拟机上安装代理”**。

**备注:** 在 Windows 虚拟机上安装代理和在非 Azure Windows 计算机上安装代理的说明可能相反。即使显示的文字相反，链接也可指向适当的位置。

10. 选择 **“为非 Azure Windows 虚拟机下载和安装代理”**。 

11. 选择 **“下载 Windows 代理(64 位)”** 的链接。

12. 运行下载的 .exe 文件，并在出现“用户帐户控制”提示时确认。

13. 在“欢迎”对话上，选择 **“下一步”**。

14. 在“Microsoft 软件许可条款”页面上选择 **“我同意”**。  在“目标”提示上选择 **“下一步”**。

15. 在“代理安装选项”提示上，选择 **“将代理连接到 Azure Log Analytics (OMS)”** 选项，然后选择 **“下一步”**。

16. 在浏览器中，从代理管理页面复制 **“工作区 ID”**，然后在对话中粘贴到“工作区 ID”。 

17. 在浏览器中，从代理管理页面复制 **“主键”**，然后在对话中粘贴到 **“主键”**。 

18. 选择 **“下一步”**。

19. 在 “Microsoft 更新”页上选择 **“下一步”**。

20. 然后选择 **“安装”**。

### 任务 4： 安装并收集 Sysmon 日志。

在此任务中，你将安装并收集 Sysmon 日志。

此时应仍连接到 WIN2 虚拟机。  以下说明将使用默认配置安装 Sysmon。  应研究基于社区的配置，以便在生产计算机上使用 Sysmon。

1. 在浏览器中，转到 https://docs.microsoft.com/sysinternals/downloads/sysmon

2. 从页面上选择 **“下载 Sysmon”** 以下载 Sysmon。

3. 打开下载文件并将文件提取到新目录 c:\sysmon

4. 在适用于 WIN2 的 Windows 任务栏搜索框中，输入 *“命令”*。  搜索结果将显示命令提示符应用。  右键单击命令提示符应用并选择 **“以管理员身份运行”**。  确认显示的任何用户帐户控制提示。

5. 输入 *cd \sysmon*

6. 加入 *notepad sysmon.xml* 以创建新文件。

7. 在浏览器中打开选项卡，并导航到 https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

8. 将该文件的内容从 Github 复制到你刚创建的 sysmon.xml 记事本文件，并保存文件。

9. 在命令提示符中键入以下命令，并按 Enter：
    sysmon.exe -accepteula -i sysmon.xml

10. 在浏览器中，导航到 Azure 门户 (https://portal.azure.com) 

11. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择 **“Azure Sentinel”**。

12. 在 Azure Sentinel 中，从“配置”区域选择 **“设置”**，然后选择 **“工作区设置”** 选项卡。

13. 确保选择你的 Azure Sentinel 工作区。

14. 在“设置”中选择 **“代理配置”**。

15. 选择 **“Windows 事件日志”** 选项卡。

16. 选择 **“添加 Windows 事件日志”** 按钮。

17. 在“日志名称”字段输入 **Microsoft-Windows-Sysmon/Operational**。

18. 选择“**应用**”。

### 任务 5：载入 Microsoft Defender for Endpoint 设备。

在此任务中，你需要将设备加入 Microsoft Defender for Endpoint。

**备注:** 如果你完成了本课程第一个模块中的实验室，则你已执行此任务。  如果要使用该实验室练习中所用的虚拟机，则无需进行此任务。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 转到 Microsoft Defender 安全中心 (https://securitycenter.microsoft.com)， 并使用 **租户电子邮件** 凭据登录（如果当前不在该门户中）。

3. 从左侧菜单栏中选择 **“设置”**。

4. 在“设备管理”部分选择 **“加入”**。

5. 选择 加入 **“下载包”**。

6. 提取下载的 .zip 文件。

7. 以**管理员**身份运行 Windows 命令提示符，并同意显示的用户帐户控制提示。

8. 运行你刚才以管理员身份提取的 WindowsDefenderATPLocalOnboardingScript.cmd 文件。**备注**：默认情况下，该文件应位于 c:\users\admin\downloads 目录中。对于脚本呈现的问题回答 Y。 

9. 从 Microsoft Defender 安全中心门户中的“加入”页面，复制检测测试脚本并在 **“管理员: 命令提示符”** 窗口中打开。

10.  在 Microsoft Defender 安全中心门户菜单中，从左导航中选择 **“设备清单”** 图标。该列表中现在应列出了你的设备。**备注**：可能需要多达 5 分钟，设备才会显示在门户中。

## 转到练习 3