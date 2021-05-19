﻿# 模块 6 - 实验室 1 - 练习 1 - 使用数据连接器将数据连接到 Azure Sentinel

## 实验室场景

你是一位安全运营分析师，你所在公司已实现 Azure Sentinel。你需要了解如何连接组织中多个不同数据源的日志数据。组织的数据来自 Microsoft 365、Microsoft 365 Defender、Azure 资源、非 Azure 虚拟机和网络设备。

你计划使用 Azure Sentinel 数据连接器集成来自各种源的日志数据。你需要编写用于管理的连接器计划，以将组织的每个数据源映射到适当的 Azure Sentinel 数据连接器。

**重要警告！**  模块 7 中使用了虚拟机 WIN1 和 WIN2。  请保存你的虚拟机。   如果不保存就退出实验室，则将需要在 WIN1 和 WIN2 上再次安装连接器。

### 任务 1：访问 Azure Sentinel 工作区。

在此任务中，你将访问 Azure Sentinel 工作区。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 打开浏览器，搜索、下载并安装新的 Microsoft Edge 浏览器。启动新的 Microsoft Edge 浏览器。

3. 在 Microsoft Edge 浏览器中，通过 https://portal.azure.com 导航到 Azure 门户。

4. 在 **“登录”** 对话框中，复制粘贴实验室托管提供者提供的**租户电子邮件**帐户，然后选择 **“下一步”**。

5. 在 **“输入密码”** 对话框中，复制粘贴实验室托管提供者提供的**租户密码**，然后选择 **“登录”**。

6. 在 Azure 门户的搜索栏中，键入 *Sentinel*，然后选择 **“Azure Sentinel”**。

7. 选择你在上一个实验室中创建的 Azure Sentinel 工作区。

### 任务 2：连接 Azure Active Directory 连接器。

在此任务中，你将连接 Azure Active Directory 连接器。

1. 在“配置”区域，选择 **“数据连接器”**。  在“数据连接器”页面中，从列表中选择 **“Azure Active Directory”** 连接器。

2. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

3. 从“配置”区域中选择 **“登录日志”** 和 **“审核日志”** 选项，然后选择 **“应用更改”**。

### 任务 3：连接 Azure Active Directory 标识保护连接器。

在此任务中，你将连接 Azure Active Directory 标识保护连接器。

1. 在“数据连接器”选项卡中，从列表中选择 **“Azure Active Directory 标识保护”** 连接器。

2. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

3. 选择 **“连接”** 按钮。

### 任务 4：连接 Azure Defender 连接器。

在此任务中，你将连接 Azure Defender 连接器。

1. 在“数据连接器”选项卡中，从列表中选择 **“Azure Defender”** 连接器。

2. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

3. 查看连接选项。请不要连接。这仅用于了解信息。

### 任务 5：连接 Microsoft Cloud App Security 连接器。

在此任务中，你将连接 Microsoft Cloud App Security 连接器。

1. 在“数据连接器”选项卡中，从列表中选择 **“Microsoft Cloud App Security”** 连接器。

2. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

3. 选择 **“警报”**，然后选择 **“应用更改”**。

### 任务 6：连接 Microsoft Defender for Office 365 连接器。

在此任务中，你将连接 Microsoft Defender for Office 365 连接器。

1. 在“数据连接器”选项卡中，从列表中选择 **“Microsoft Defender for Office 365”** 连接器。

2. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

3. 选择 **“连接”**。

### 任务 7：连接 Microsoft Defender for Identity 连接器。

在此任务中，你将连接 Microsoft Defender for Identity 连接器。

1. 在“数据连接器”选项卡中，从列表中选择 **“Microsoft Defender for Identity”** 连接器。

2. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

3. 查看连接选项。请不要连接。这仅用于了解信息。

### 任务 8：连接 Microsoft Defender for Endpoint 连接器。

在此任务中，你将连接 Microsoft Defender for Endpoint 连接器。

1. 在“数据连接器”选项卡中，从列表中选择 **“Microsoft Defender for Endpoint”** 连接器。

2. 在连接器信息边栏选项卡上选择“打开连接器页面”。

3. 选择 **“连接”**。

### 任务 9：连接 Microsoft 365 Defender 连接器。

在此任务中，你将连接 Microsoft 365 Defender 连接器。

1. 在“数据连接器”选项卡中，从列表中选择 **“Microsoft 365 Defender”**。

2. 在连接器信息边栏选项卡上选择 **“打开连接器页面”**。

3. 选中 Microsoft Defender for Endpoint 的所有复选框。

4. 选择 **“应用更改”**。

## 转到练习 2