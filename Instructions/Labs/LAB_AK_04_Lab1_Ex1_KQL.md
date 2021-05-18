# 模块 4 - 实验室 1 - 练习 1 - 使用 Kusto 查询语言 (KQL) 为 Azure Sentinel 创建查询

## 实验室场景
你是一位安全运营分析师，你所在公司正在实现 Azure Sentinel。你负责执行日志数据分析，以便搜索恶意活动、显示可视化效果并执行威胁搜寻。为了查询日志数据，你使用 Kusto 查询语言 (KQL)。

### 任务 1：访问 KQL 测试区域。

在此任务中，你将访问 Log Analytics 环境，可在其中练习编写 KQL 语句。

1. 使用以下密码以管理员身份登录到 WIN1 虚拟机：**Pa55w.rd**。  

2. 在浏览器中转到 https://aka.ms/lademo。使用 MOD 管理员凭据登录。 

3. 浏览屏幕左侧选项卡中列出的可用表。

4. 在查询编辑器中，输入以下查询，然后选择“运行”按钮。  你应该会在底部窗口中看到查询结果。

```KQL
SecurityEvent
```

5. 在第一条记录旁边，选择 **“>”** 以展开该行的信息。

### 任务 2：运行基本的 KQL 语句

在此任务中，你将生成基本的 KQL 语句。

1. 下面的语句演示了将 let 语句用于声明变量的用法。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
let timeOffset = 7d;
let discardEventId = 4688;
SecurityEvent
| where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
| where EventID != discardEventId

```

2. 以下语句演示了将 let 语句用于声明动态列表的用法。在查询窗口中，输入以下语句，然后选择 **“运行”**： 


```KQL
let suspiciousAccounts = datatable(account: string) [
    @"\administrator", 
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent | where Account in (suspiciousAccounts)
```

3. 以下语句演示了将 let 语句用于声明动态表的用法。在查询窗口中，输入以下语句并选择 **“运行”**： 

```KQL
let LowActivityAccounts =
    SecurityEvent 
    | summarize cnt = count() by Account 
    | where cnt < 10;
LowActivityAccounts | where Account contains "Mal"

```
**备注:** 运行此脚本时，应该不会获得任何结果。

4. 以下语句演示了查询窗口中显示的在所有表和列中搜索查询时间范围内的记录。在运行此脚本之前，在查询窗口中，将时间范围更改为“过去一小时”。输入以下语句并选择 **“运行”**： 

```KQL
search "err"
```

**警告：** 请务必在后续脚本中将时间范围改回“过去 24 小时”。

5. 以下语句演示了查询窗口中显示的在所有通过“in”子句中列出的表中搜索查询时间范围内的记录。在查询窗口中，输入以下语句并选择 **“运行”**： 

```KQL
search in (SecurityEvent,SecurityAlert,A*) "err"
```


6. 以下语句演示了使用 where 运算符的筛选器。在查询窗口中，输入以下语句并选择 **“运行”**： 

**备注:** 在下面的每个代码块中输入查询后，你应该“运行”。

```KQL
SecurityEvent
| where TimeGenerated > ago(1d)
```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4624"

```

```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where AccountType =~ "user"

```

```KQL
SecurityEvent | where EventID in (4624, 4625)
```


7. 以下语句演示了在查询窗口中使用 extend 运算符创建字段的方法。输入以下语句并选择 **“运行”**： 


```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)

```


8. 下面的语句演示了一个实际示例，该示例结合了 let、动态列表创建以及使用 extend 创建字段。在查询窗口中，输入以下语句并选择“运行”： 

```KQL
let timeframe = 1d;
let DomainList = dynamic(["tor2web.org", "tor2web.com"]);
Syslog
| where TimeGenerated >= ago(timeframe)
| where ProcessName contains "squid"
| extend 
  HTTP_Status_Code = extract("(TCP_(([A-Z]+)…-9]{3}))",8,SyslogMessage),    
  Domain = extract("(([A-Z]+ [a-z]{4…Z]+ )([^ :\\/]*))",3,SyslogMessage)
| where HTTP_Status_Code == "200"
| where Domain contains "."
| where Domain has_any (DomainList)

```

**备注:** 运行此脚本时，应该不会获得任何结果。

9. 以下语句演示了如何使用 order by 运算符对结果进行排序。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
| order by severityOrder desc

```

10. 以下语句演示如何使用 project 运算符为结果集指定字段。

**备注:** 在下面的每个代码块中输入查询后，你应该“运行”。

在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
SecurityEvent
| project Computer, Account


```



```KQL
SecurityAlert
| where TimeGenerated > ago(7d)
| extend severityOrder = case (
    AlertSeverity == "High", 3,
    AlertSeverity == "Medium", 2, 
    AlertSeverity == "Low", 1,
    AlertSeverity == "Informational", 0,
    -1)
| order by severityOrder
| project-away severityOrder



```

### 任务 3： 使用 Summarize 运算符分析 KQL 中的结果

在此任务中，你将生成 KQL 语句来准备数据。

1. 以下语句演示了 count 函数。在查询窗口中，输入以下语句并选择 **“运行”**： 



```KQL
SecurityEvent
| where EventID == "4688"
| summarize count() by Process, Computer

```


2. 以下语句演示了 count 函数。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| summarize cnt=count() by AccountType, Computer

```



3. 以下语句演示了 dcount 函数。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
SecurityEvent
| summarize dcount(IpAddress)

```

4. 下面的语句是一个 Azure Sentinel 分析规则，用于检测密码喷射尝试。

前三个 where 运算符筛选结果集来显示已禁用帐户的失败登录。  接下来，语句按用户和 IP 地址“汇总”应用程序名称和组的非重复计数。  最后，对照创建的变量（阈值）进行检查，查看该数字是否超过允许的数量。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
let timeframe = 1d;
let threshold = 3;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultType == "50057"
| where ResultDescription =~ "User account is disabled. The account has been disabled by an administrator."
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold


```
**备注:** 运行此脚本时，应该不会获得任何结果。

5. 以下语句演示了 arg_max 函数。

以下语句将返回计算机 SQL12.NA.contosohotels.com 的 SecurityEvent 表中的最新行。  arg_max 函数中的 * 请求该行的所有列。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
SecurityEvent 
| where Computer == "SQL12.na.contosohotels.com"
| summarize arg_max(TimeGenerated,*) by Computer

```

6. 以下语句演示了 arg_min 函数。

在此语句中，计算机 SQL12.NA.contosohotels.com 的最早 SecurityEvent 将作为结果集返回。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
SecurityEvent 
| where Computer == "SQL12.na.contosohotels.com"
| summarize arg_min(TimeGenerated,*) by Computer

```

7. 以下语句演示了根据竖线 “|” 顺序理解结果的重要性。在查询窗口中，输入以下语句并分别运行： 

语句 1
```KQL
SecurityEvent
| summarize arg_max(TimeGenerated, *) by Account
| where EventID == "4624"

```

语句 2
```KQL
SecurityEvent
| where EventID == "4624"
| summarize arg_max(TimeGenerated, *) by Account

```
语句 1 将具有最后一个活动是登录的帐户。

首先汇总 SecurityEvent 表并返回每个帐户的最新行。  然后，将只返回 EventID 等于 4624（登录）的行。

语句 2 将具有已登录的帐户的最新登录。  

SecurityEvent 表将被筛选为仅包含 EventID = 4624。然后，将按帐户为最新登录行汇总这些结果。

8. 以下语句演示了 make_list 函数。

该函数返回组中所有表达式值的动态 (JSON) 数组。此 KQL 查询将首先使用 where 运算符筛选 EventID。  接下来，对于每台计算机，结果都是帐户的 JSON 数组。生成的 JSON 数组将包含重复的帐户。

在查询窗口中，输入以下语句并选择“运行”： 

```KQL
SecurityEvent
| where EventID == "4624"
| summarize make_list(Account) by Computer

```

9. 以下语句演示了 make_list 函数。

make_list 返回一个包含表达式在组中采用的非重复值的动态 (JSON) 数组。此 KQL 查询将首先使用 where 运算符筛选 EventID。  接下来，对于每台计算机，结果都是唯一帐户的 JSON 数组。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
SecurityEvent
| where EventID == "4624"
| summarize make_set(Account) by Computer

```

### 任务 4： 使用 Render 运算符以 KQL 创建可视化效果

在此任务中，你将使用 KQL 语句生成可视化效果。

1. 以下语句演示了使用条形图直观呈现结果的 render 函数。在查询窗口中，输入以下语句并选择 **“运行”**： 

```KQL
SecurityEvent 
| summarize count() by Account
| render barchart

```

2. 以下语句演示了使用时序直观呈现结果的 render 函数。

bin() 函数将值向下舍入为给定装箱大小的整数倍数。  经常与汇总依据一起使用....如果你有一组分散的值，则这些值将分组为更小的一组特定值。  将生成的时序和 render 运算符的管道与一种时间图表类型结合，可以提供时序可视化效果。在查询窗口中，输入以下语句并选择 **“运行”**： 

```KQL
SecurityEvent 
| summarize count() by bin(TimeGenerated, 1d) 
| render timechart

```

### 任务 5： 使用 KQL 生成多表语句

在此任务中，你将生成多表 KQL 语句。

1. 以下语句演示了 union 运算符，该运算符采用两个或多个表，并返回所有表的行。有必要了解结果是如何通过竖线字符传递的，又是如何受到该字符影响的。根据“查询”窗口中设置的时间范围：

查询 1 将返回 SecurityEvent 所有的行和 SecurityAlert 所有的行

查询 2 将返回一行和一列，也就是 SecurityEvent 所有的行和 SecurityAlert 所有的行的计数

查询 3 将返回 SecurityEvent 所有的行和 SecurityAlert 的一个行。  SecurityAlert 的行将具有 SecurityAlert 行的计数。

分别运行每个查询以查看结果。 

在查询窗口中，输入以下语句并对各语句选择 **“运行”**： 


查询 1
```KQL
SecurityEvent 
| union SecurityAlert  


```

查询 2
```KQL
SecurityEvent 
| union SecurityAlert  
| summarize count() 
| project count_


```
查询 3
```KQL
SecurityEvent 
| union (SecurityAlert  | summarize count()) 
| project count_


```

2. 以下语句演示了 union 运算符对通配符的支持，以联合多个表。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
union Security* 
| summarize count() by Type

```


3. 以下语句演示了 join 运算符，该运算符通过匹配每个表中指定列的值来合并两个表的行以形成新表。在查询窗口中，输入以下语句并选择 **“运行”**： 


```KQL
SecurityEvent 
| where EventID == "4624" 
| summarize LogOnCount=count() by EventID, Account 
| project LogOnCount, Account 
| join kind = inner (
     SecurityEvent 
     | where EventID == "4634" 
     | summarize LogOffCount=count() by EventID, Account 
     | project LogOffCount, Account 
) on Account


```

联接中指定的第一个表被看作是左表。  联接关键字后面的表被看作是右表。  处理表中的列时，名称 $left.Column 和 $right.Column 用于区分正在引用哪个表的列。 

### 任务 6：使用 KQL 处理字符串数据

在此任务中，你将使用 KQL 语句处理结构化和非结构化的字符串字段。

1. 以下语句演示了 extract 函数。  extract 从文本字符串中获取正则表达式的匹配项。可以选择将提取的子字符串转换为指定的类型。在查询窗口中，输入以下语句并选择 **“运行”**： 

```KQL
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"
```

2. 以下语句使用 extract 函数从 SecurityEvent 表的“帐户”字段中提取“帐户名称”。在查询窗口中，输入以下语句并选择 **“运行”**： 



```KQL
let top5 = SecurityEvent
| where EventID == 4625 and AccountType == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| summarize Attempts = count() by Account_Name
| where Account_Name != ""
| top 5 by Attempts 
| summarize make_list(Account_Name);

SecurityEvent
| where EventID == 4625 and AccountType == 'User'
| extend Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| extend Account_Name = iff(Name in (top5), Name, "Other")
| where Account_Name != ""
| summarize Attempts = count() by Account_Name

```

3. 以下语句演示了 parse 函数。  计算字符串表达式并将其值分析为一个或多个计算列。对于未成功分析的字符串，计算列的值将为 null。

查看以下语句，但不要运行： 

```KQL
let SQlData = Event
| where Source has "MSSQL"
;
let Sqlactivity = SQlData
| where RenderedDescription !has "LGIS" and RenderedDescription !has "LGIF"
| parse RenderedDescription with * "action_id:" Action:string 
                                    " " * 
| parse RenderedDescription with * "client_ip:" ClientIP:string
" permission" * 
| parse RenderedDescription with * "session_server_principal_name:" CurrentUser:string
" " * 
| parse RenderedDescription with * "database_name:" DatabaseName:string
"schema_name:" Temp:string
"object_name:" ObjectName:string
"statement:" Statement:string
"." *
;
let FailedLogon = SQlData
| where EventLevelName has "error"
| where RenderedDescription startswith "Login"
| parse kind=regex RenderedDescription with "Login" LogonResult:string
                                            "for user '" CurrentUser:string 
                                            "'. Reason:" Reason:string 
                                            "provided" *
| parse kind=regex RenderedDescription with * "CLIENT" * ":" ClientIP:string 
                                            "]" *
;
let dbfailedLogon = SQlData
| where RenderedDescription has " Failed to open the explicitly specified database" 
| parse kind=regex RenderedDescription with "Login" LogonResult:string
                                            "for user '" CurrentUser:string 
                                            "'. Reason:" Reason:string 
                                            " '" DatabaseName:string
                                            "'" *
| parse kind=regex RenderedDescription with * "CLIENT" * ":" ClientIP:string 
                                            "]" *
;
let successLogon = SQlData
| where RenderedDescription has "LGIS"
| parse RenderedDescription with * "action_id:" Action:string 
                                    " " LogonResult:string 
                                    ":" Temp2:string
                                    "session_server_principal_name:" CurrentUser:string
                                    " " *
| parse RenderedDescription with * "client_ip:" ClientIP:string 
                                    " " *
;
(union isfuzzy=true
Sqlactivity, FailedLogon, dbfailedLogon, successLogon )
| project TimeGenerated, Computer, EventID, Action, ClientIP, LogonResult, CurrentUser, Reason, DatabaseName, ObjectName, Statement

```

4. 以下语句演示了如何使用动态字段：

Log Analytics 表中有一个定义为“动态”的字段类型。  动态字段包含键值对，如：
{"eventCategory":"Autoscale","eventName":"GetOperationStatusResult","operationId":"xxxxxxxx-6a53-4aed-bab4-575642a10226","eventProperties":"{\"OldInstancesCount\":6,\"NewInstancesCount\":5}","eventDataId":" xxxxxxxx -efe3-43c2-8c86-cd84f70039d3","eventSubmissionTimestamp":"2020-11-30T04:06:17.0503722Z","resource":"ch-appfevmss-pri","resourceGroup":"CH-RETAILRG-PRI","resourceProviderValue":"MICROSOFT.COMPUTE","subscriptionId":" xxxxxxxx -7fde-4caf-8629-41dc15e3b352","activityStatusValue":"Succeeded"}

若要访问动态字段中的字符串，请使用点表示法。  AzureActivity 表中的 “Properties_d” 字段属于动态类型。在此示例中，可以使用 “Properties_d.eventCategory” 字段名称访问 eventCategory。

在查询窗口中，输入以下语句并**运行**： 

```KQL
AzureActivity
| project Properties_d.eventCategory

```

**备注:** 运行此脚本时，应该不会获得任何结果。

仅查看以下语句，但不要运行： 

```KQL
SigninLogs 
| where TimeGenerated >= ago(1d)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend ConditionalAccessPol0Name = tostring(ConditionalAccessPolicies[0].displayName), ConditionalAccessPol0Result = tostring(ConditionalAccessPolicies[0].result)
| extend ConditionalAccessPol1Name = tostring(ConditionalAccessPolicies[1].displayName), ConditionalAccessPol1Result = tostring(ConditionalAccessPolicies[1].result)
| extend ConditionalAccessPol2Name = tostring(ConditionalAccessPolicies[2].displayName), ConditionalAccessPol2Result = tostring(ConditionalAccessPolicies[2].result)
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
| extend Date = startofday(TimeGenerated), Hour = datetime_part("Hour", TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, ConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, Location, State, City
| sort by Date

```

5. 以下语句演示了用于操作存储在字符串字段中的 JSON 的函数。许多日志以 JSON 格式提交数据，这要求了解如何将 JSON 数据转换为可查询字段。 

在查询窗口中，分别输入以下语句并选择 **“运行”**： 

```KQL
SecurityAlert
| extend ExtendedProperties = todynamic(ExtendedProperties) 
| extend ActionTaken = ExtendedProperties.ActionTaken
| extend AttackerIP = ExtendedProperties["Attacker IP"]

```


```KQL
SecurityAlert
| mv-expand entity = todynamic(Entities)

```


```KQL
SecurityAlert
| where TimeGenerated >= ago(7d)
| mv-apply entity = todynamic(Entities) on 
( where entity.Type == "account" | extend account = strcat (entity.NTDomain, "\\", entity.Name))

```

6. 分析程序是定义虚拟表（具有已分析的非结构化字符串字段，例如 Syslog 数据）的函数。下面是社区为邮箱转发监视创建的 KQL 查询。  

查看以下语句，但不要运行： 

```KQL
OfficeActivity
    | where TimeGenerated >= ago(30d)
    | where Operation == 'New-InboxRule'
    | extend details = parse_json(Parameters)
    | where details contains 'ForwardTo' or details contains 'RedirectTo'
    | extend ForwardTo = iif(details[0].Name contains 'ForwardTo', details[0].Value,
        iif(details[1].Name contains 'ForwardTo', details[1].Value, 
            iif(details[2].Name contains 'ForwardTo', details[2].Value,  
                iif(details[3].Name contains 'ForwardTo', details[3].Value, 
                    iif(details[4].Name contains 'ForwardTo', details[4].Value,
                        'Check Parameters')))))
    | extend RedirectTo = iif(details[0].Name contains 'RedirectTo', details[0].Value,
        iif(details[1].Name contains 'RedirectTo', details[1].Value,
            iif(details[2].Name contains 'RedirectTo', details[2].Value,
                iif(details[3].Name contains 'RedirectTo', details[3].Value,
                    iif(details[4].Name contains 'RedirectTo', details[4].Value,
                        'Check Parameters')))))
    | extend RuleName = iif(details[3].Name contains 'Name', details[3].Value,
         iif(details[4].Name contains 'Name', details[4].Value,
            iif(details[5].Name contains 'Name', details[5].Value,
                'Check Parameters')))
    | extend RuleParameters = iif(details[2].Name != 'ForwardTo' and  details[2].Name != 'RedirectTo', 
        strcat(tostring(details[2].Name), '-', tostring(details[2].Value)),
        iif(details[3].Name != 'ForwardTo' and  details[3].Name != 'RedirectTo' and details[3].Name != 'Name',
            strcat(tostring(details[3].Name), '-', tostring(details[3].Value)), 
                iff(details[4].Name != 'ForwardTo' and details[4].Name != 'RedirectTo' and details[4].Name != 'Name' and details[4].Name != 'StopProcessingRules',
                strcat(tostring(details[4].Name), '-', tostring(details[4].Value)),
                'All Mail')))
    | project TimeGenerated, Operation, RuleName, RuleParameters, iif(details contains 'ForwardTo', ForwardTo, RedirectTo), ClientIP, UserId
    | project-rename Email_Forwarded_To = Column1, Creating_User = UserId


```

若要创建函数：

运行查询后，单击“保存”按钮，输入名称：MailboxForward，然后从下拉菜单中选择“另存为函数”。   

通过使用函数别名，该功能将以 KQL 提供：

**备注:** 在用于本实验室中数据的 lademo 环境中，你将无法执行此操作，但这是你的环境中要使用的重要概念。 

```KQL
MailboxForward
```

## 你已完成本实验室。

