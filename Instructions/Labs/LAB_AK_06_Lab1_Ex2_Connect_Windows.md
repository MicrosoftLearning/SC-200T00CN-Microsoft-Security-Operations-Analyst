---
lab:
    title: '练习 2 - 使用数据连接器将 Windows 设备连接到 Microsoft Sentinel'
    module: '模块 6 - 将日志连接到 Microsoft Sentinel'
---

# 模块 6 - 实验室 1 - 练习 2 - 使用数据连接器将 Windows 设备连接到 Microsoft Sentinel


### 任务 1： 在 Azure 中创建 Windows 虚拟机。

在本任务中，你将在 Azure 中创建 Windows 虚拟机。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 在 Microsoft Edge 浏览器中，通过 https://portal.azure.com 导航到 Azure 门户。

3. 在 **“登录”** 对话框中，复制粘贴实验室托管提供者提供的**租户电子邮件**帐户，然后选择 **“下一步”**。

4. 在 **“输入密码”** 对话框中，复制粘贴实验室托管提供者提供的**租户密码**，然后选择 **“登录”**。

5. 选择“**+ 创建资源**”。如果已在 Azure 门户中，则可能需要从顶部栏中选择“*Microsoft Azure*”以返回主页。

6. 在 **“搜索服务和市场”** 框中，输入 *“Windows 10”*。 

7. 选择 Microsoft Windows 10 的 **“创建”** 下拉列表。  然后选择 **“Windows 10 企业版，版本 20H2”**。

8. 选择你的订阅。

9. 选择“**新建**”来新建*资源组*，输入 RG-AZWIN01 作为名称，然后选择“**确定**”。

    >**备注**：该资源组应是用于跟踪的新资源组。  

10. 在“*虚拟机名称*”中输入 AZWIN01。

11. 将“*区域*”设置为你的地区的相应区域。  可能会默认设置相应区域。

12. 对于“**可用性选项**”，请选择“**无需基础结构冗余**”。

13. 输入你选择的 Azure 可接受的*用户名*。

14. 输入你选择的密码。 

    >**提示：** 使用你的租户密码可能最简单。

15. 选择“*许可*”下的复选框。

16. 选择 **“查看 + 创建”**。

17. 选择 **“创建”**。等待创建资源，这可能需要几分钟的时间。


### 任务 2：连接 Azure Windows 虚拟机。

在此任务中，你要将 Azure Windows 虚拟机连接到 Microsoft Sentinel。

1. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择“**Microsoft Sentinel**”。

2. 选择之前创建的 Microsoft Sentinel 工作区。

3. 在“数据连接器”选项卡中，从列表搜索“**通过旧式代理的安全事件**”连接器并将其选中。

4. 在连接器信息边栏选项卡上选择“**打开连接器页面**”。

5. 选择“**在 Azure Windows 虚拟机上安装代理**”选项。

6. 选择“**为 Azure Windows 虚拟机下载和安装代理**”。

7. 在上一任务中创建的列表中选择 **AZWIN01** 虚拟机，然后选择“**连接**”。等待“*连接...*”消息消失。

8. 选择“x”关闭窗口，返回到“**虚拟机**”视图。此时应显示虚拟机有一个到此工作区的 *Log Analytics 连接*。


### 任务 3：连接非 Azure Windows 计算机。

在此任务中，你要将非 Azure Windows 虚拟机连接到 Microsoft Sentinel。

1. 以管理员身份使用密码登录到 WIN2 虚拟机：**Pa55w.rd**。  

2. 打开 Microsoft Edge 浏览器。

3. 打开浏览器，并使用在先前的实验室中使用的凭据登录 Azure 门户 (https://portal.azure.com)。

4. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择“**Microsoft Sentinel**”。

5. 选择 Microsoft Sentinel 工作区。

6. 选择“**数据连接器**”，然后从列表搜索“**通过旧式代理的安全事件**”连接器并将其选中。

7. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

8. 在“选择要流式传输的事件”区域，选择 **“所有事件”**，然后选择 **“应用更改”**。

9. 选择 **“在非 Azure Windows 计算机上安装代理”**。

10. 选择 **“为 Azure Windows 计算机下载和安装代理”**。 

11. 选择 **“下载 Windows 代理(64 位)”** 的链接。

12. 打开下载的“*MMASetup-AMD64.exe*”文件，选择“**是**”，允许可执行文件在出现的“用户帐户控件”窗口中运行。

13. 在“欢迎”对话上，选择 **“下一步”**。

14. 在“Microsoft 软件许可条款”页面上选择 **“我同意”**。  在“目标”提示上选择 **“下一步”**。

15. 在“代理安装选项”提示上，选择 **“将代理连接到 Azure Log Analytics (OMS)”** 选项，然后选择 **“下一步”**。

16. 在打开了 Microsoft Sentinel 的浏览器中，从“代理管理”页复制“**工作区 ID**”，然后将工作区 ID 粘贴到对话框中。 

17. 在打开了 Microsoft Sentinel 的浏览器中，从“代理管理”页复制“**主密钥**”，然后将工作区密钥粘贴到对话框中。 

18. 选择 **“下一步”**。

19. 在 “Microsoft 更新”页上选择 **“下一步”**。

20. 然后选择 **“安装”**。  完成后，选择 **“完成”**。


### 任务 4： 安装并收集 Sysmon 日志。

在此任务中，你将安装并收集 Sysmon 日志。

>**重要提示**： 此时应仍连接到 WIN2 虚拟机。以下说明将使用默认配置安装 Sysmon。应研究基于社区的配置，以便在生产计算机上使用 Sysmon。

1. 在浏览器中打开一个新的标签页，转到 https://docs.microsoft.com/sysinternals/downloads/sysmon

2. 在页面上，选择 **“下载 Sysmon”** 以下载 Sysmon。

3. 将鼠标悬停在 *Sysmon.zip* 上，并选择文件夹图标。右键单击下载的文件并选择“**全部提取…**”，在“文件将提取到此文件夹”下选择 *C:\Sysmon*，然后选择“**提取**”。 

4. 在适用于 WIN2 的 Windows 任务栏搜索框中，输入“*命令*”。 搜索结果将显示命令提示符应用。  右键单击命令提示符应用，并选择“**以管理员身份运行**”。  选择“是”，允许应用在出现的“**用户帐户控制**”窗口中运行。

5. 输入 *cd \sysmon*

6. 键入“*notepad sysmon.xml*”以创建新文件。选择“**是**”以确认创建文件。

7. 在浏览器中打开一个新的标签页，转到 https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

8. 选择“**原始**”按钮，并将该文件的内容从 GitHub 复制到你刚刚创建的 sysmon.xml 记事本文件中。选择“**文件**”，然后选择“**保存**”以保存文件。

9. 在命令提示符中键入以下命令，并按 Enter：
    **sysmon.exe -accepteula -i sysmon.xml**

    >**备注：**  验证输出中是否出现“已验证配置文件”和“已启动 Sysmon”消息。如果未出现，请验证数据是否复制正确以及是否已保存 sysmon.xml。

10. 在浏览器中，导航回到 Azure 门户 (https://portal.azure.com)。 

11. 在 Azure 门户的“搜索”栏中，键入 *Sentinel*，然后选择 **Microsoft Sentinel**，并选择之前创建的 Microsoft Sentinel 工作区。

12. 在 Microsoft Sentinel 中，从“配置”区域中选择“**设置**”，然后选择“**工作区设置>**”选项卡。

13. 确保选择你的 Microsoft Sentinel 工作区。

14. 在“设置”区域中，选择 **“代理配置”**。

15. 选择 **“Windows 事件日志”** 选项卡。

16. 选择 **“添加 Windows 事件日志”** 按钮。

17. 在“日志名称”字段中键入“**Microsoft-Windows-Sysmon/Operational**”。

18. 选择“**应用**”。


### 任务 5：载入 Microsoft Defender for Endpoint 设备。

在此任务中，你需要将设备加入 Microsoft Defender for Endpoint。

>**重要提示**：如果你完成了本课程第一个模块中的实验室并保存了虚拟机，则已经完成了这项任务。这意味着如果使用的是该实验室练习中使用的虚拟机，可跳过此任务。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 如果当前不在门户中，请通过 Microsoft Edge 浏览器转到 Microsoft 365 Defender 门户 (https://security.microsoft.com) 并使用**租户电子邮件**凭据登录。

3. 从左侧菜单栏中选择“设置”，然后从 **“设置”** 页面中选择 **“终结点”**。

4. 在“设备管理”部分选择 **“加入”**。

5. 选择 加入 **“下载包”**。

6. 提取下载的 .zip 文件。

7. 以**管理员**身份运行 Windows 命令提示符，并同意显示的用户帐户控制提示。

8. 运行你刚才以管理员身份提取的 WindowsDefenderATPLocalOnboardingScript.cmd 文件。**备注**：默认情况下，该文件应位于 c:\users\admin\downloads 目录中。对于脚本呈现的问题回答 Y。 

9. 从门户的“加入”页面中，复制检测测试脚本，并在一个打开的命令窗口中运行该脚本。  你可能需要通过在 Windows 搜索栏中键入*CMD*，然后选择 **“以管理员身份运行”** 来打开新的 **“管理员: 命令提示符”** 窗口。

10. 在 Microsoft 365 Defender 门户的“终结点”区域中，选择 **“设备清单”**。该列表中现在应列出了你的设备。

## 转到练习 3
