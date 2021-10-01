# ģ�� 7 - ʵ���� 1 - ��ϰ 6 - �������

### ���� 1��ʹ�� Sysmon ��⹥�� 1

�ڴ������У��㽫�ڰ�װ�˰�ȫ�¼��������� Sysmon �������ϴ�����Թ��� 1 �ļ�⡣

�˹����ᴴ��һ��������ʱ���е�ע����  
```Command
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

1. ʹ�����������Թ���Ա��ݵ�¼�� WIN1 �������**Pa55w.rd**��  

2. �� Microsoft Edge ������У�ͨ�� https://portal.azure.com ������ Azure �Ż���

3. �� **����¼��** �Ի����У�����ճ��ʵ�����й��ṩ��Ϊ����Ա�ṩ��**�⻧�����ʼ�**�ʻ���Ȼ��ѡ�� **����һ����**��

4. �� **���������롱** �Ի����У�����ճ��ʵ�����й��ṩ��Ϊ����Ա�ṩ��**�⻧����**��Ȼ��ѡ�� **����¼��**��

5. �� Azure �Ż����������У����� *Sentinel*��Ȼ��ѡ�� **��Azure Sentinel��**��

6. ѡ��֮ǰ������ Azure Sentinel ��������

7. �ӡ����桱����ѡ�� **����־��**��

8. ������Ҫ�鿴�洢���ݵ�λ�á�ԭ������ո�ִ���˹�����  ����־ʱ�䷶Χ����Ϊ **����ȥ 24 Сʱ��**��

9. �������� KQL ���

```KQL
search "temp\\startup.bat"
```

10. ��� 3 ����ͬ�ı���ʾ�����
    - DeviceProcessEvents
    - DeviceRegistryEvents
    - Event

    *�豸*������ Defender for Endpoint������������ - Microsoft 365 Defender����  *�¼�*����������������ȫ�¼��� 

    ���ǽ���������������ͬԴ��Sysmon �� Defender for Endpoint�������ݣ������Ҫ��������֮������ϵ� KQL ��䡣  ���ε���ʱ���㽫�ֱ�鿴ÿ�����ݡ�

    **��ע��** �ڼ���������£����ݼ��ع��̿�����Ҫ��������������ļ���ʱ�䡣  �����������ʱ����Щ������ڼ���Сʱ�ڶ���������ڲ�ѯ�С�

11. ��һ������Դ�� Windows �����е� Sysmon��  �������� KQL ��䡣

```KQL
search in (Event) "temp\\startup.bat"
```
���ڽ���ʾ Event ��Ľ����  

12. չ�����пɲ鿴���¼��ص������С�  һЩ�ֶΣ����� EventData �� ParameterXml�����ж���洢Ϊ�ṹ�����ݵ������  ��ʹ�ú��Ѷ��ض��ֶν��в�ѯ��  

13. ��������������Ҫ����һ���ɷ���ÿ�������ݵ� KQL ��䣬�Ӷ��õ���������ֶΡ�  �� GitHub �ϵ� Azure Sentinel �����У������������ļ������ṩ�˺ܶ��������ʾ����  ��������д���һ����ǩҳ��Ȼ�󵼺�����https://github.com/Azure/Azure-Sentinel

14. ѡ�� **����������** �ļ��У�Ȼ��ѡ�� **��Sysmon��** �ļ��С�  Ӧ�ῴ���������ݣ�Azure-Sentinel/Parsers/Sysmon/Sysmon-v12.0.txt

15. ѡ��Ҫ�鿴�� Sysmon-v12.0.txt �ļ���

���ļ���������ῴ��һ�� Let ��䣬�����ڲ�ѯ Event ���洢����Ϊ EventData �ı����С�


```KQL
let EventData = Event
| where Source == "Microsoft-Windows-Sysmon"
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| project TimeGenerated, Source, EventID, Computer, UserName, EventData, RenderedDescription
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| project-away EventData, EvData  ;
```

���ļ����Ժ󲿷֣�����ٿ���һ�� Let ��䣬����ʾ EventID == 13 ���� EventData �����������롣  

```KQL
let SYSMON_REG_SETVALUE_13=()
{
    let processEvents = EventData
    | where EventID == 13
    | extend RuleName = EventDetail.[0].["#text"], EventType = EventDetail.[1].["#text"], UtcTime = EventDetail.[2].["#text"], ProcessGuid = EventDetail.[3].["#text"], 
    ProcessId = EventDetail.[4].["#text"], Image = EventDetail.[5].["#text"], TargetObject = EventDetail.[6].["#text"], Details = EventDetail.[7].["#text"]
    | project-away EventDetail  ;
    processEvents;
    
};
```
���������ֲ���

16. ʹ��������䴴�����Լ��� KQL ��䣬����ʾ���еġ�ע����ֵ���С�  �������� KQL ��ѯ��

```KQL

Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])
| project TimeGenerated, Source, EventID, Computer, UserName, EventData, RenderedDescription
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| project-away EventData, EvData  
| extend RuleName = EventDetail.[0].["#text"], EventType = EventDetail.[1].["#text"], UtcTime = EventDetail.[2].["#text"], ProcessGuid = EventDetail.[3].["#text"], 
    ProcessId = EventDetail.[4].["#text"], Image = EventDetail.[5].["#text"], TargetObject = EventDetail.[6].["#text"], Details = EventDetail.[7].["#text"]
    | project-away EventDetail 


```

   ![��Ļ��ͼ](../Media/SC200_sysmon_query1.png)

17.  �ɴ�����������ɼ����򣬵��� KQL ����ƺ���������������� KQL ������ظ�ʹ�á�  �ڡ���־�������У�ѡ�� **�����桱**��Ȼ��ѡ�� **������Ϊ������**���ڡ����桱�ɳ�ʽ�����У�����������Ϣ�����溯����

�������ƣ�Event_Reg_SetValue
���Sysmon


18. ���µġ���־��ѯ��ѡ���Ȼ���������� KQL ��䣺

```KQL

Event_Reg_SetValue

```
���ݵ�ǰ�����ݼ��ϣ���ɽ��ն���С�  ����Ԥ��֮�С�  ��һ��������ɸѡ�ض�������

19. �������� KQL ��䣺

```KQL

Event_Reg_SetValue | search "startup.bat"

```
�⽫�����ض���¼�������ֿɲ鿴���ݣ��˽����ǿɸ�����Щ��������ʶ�С�

20. ͨ����в�鱨�������˽⵽��в����������ʹ�� reg.exe ���ע����  Ŀ¼Ϊ c:\temp���ɽ� startup.bat ��Ϊ�������ơ��������½ű�

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"

```
����һ������Ŀ�ʼ��  ������������Ҫ������ c:\temp Ŀ¼�����ݷ��ؽ����

21. Ȼ���������� KQL ��䣺

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"
| where Details startswith "C:\\TEMP"
```

�����������������  

22. ����ؾ����ܶ���ṩ���ھ����������ģ�Ϊ��ȫ��Ӫ����ʦ�ṩ�����������ͶӰ�ڵ����ϵͼ��ʹ�õ�ʵ�塣  �������²�ѯ��

```KQL
Event_Reg_SetValue 
| where Image contains "reg.exe"
| where Details startswith "C:\\TEMP"
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = UserName

```

23. ������׼�����˼������ڰ�����ѯ����־�����У�ѡ���������е� **��+ �½���������**��Ȼ��ѡ�� **������ Azure Sentinel ������**��

24. ����������������򵼡�  �ڡ����桱ѡ��У����룺

    ���ƣ�Sysmon Startup RegKey

    ������c:\temp �е� Sysmon Startup Regkey

    ���ԣ�������

    �����ԣ���

ѡ�� **����һ��: ���ù����߼� >��**��

25. �� **�����ù����߼���** ѡ��ϣ�Ӧ��������� **�������ѯ��**��

26. ���ڲ�ѯ�ƻ������������

- ���в�ѯ��ʱ������5 ����
- �鿴�����õ����ݣ�1 ��

**��ע**�⣬�����������ͬһ���������˶���¼���  ������ʵ���ҾͿ�ʹ����Щ������

27. ������ѡ���ΪĬ��ֵ��  ѡ�� **����һ��: �¼����� >��** ��ť��

28. ���ڡ��¼����á������������ 

- �¼����ã�������
- �������飺�ѽ���

ѡ�� **����һ��: �Զ���Ӧ >��** ��ť��

29. ���ڡ��Զ���Ӧ��ѡ������������

- ѡ�� *��PostMessageTeams-OnAlert��*��

ѡ�� **����һ��: �鿴��** ��ť��

30. �ڡ��鿴��ѡ��У�ѡ�� **��������** ��ť��


### ���� 2�� ʹ�� Defender for Endpoint ��⹥�� 1

�ڴ������У��㽫�������� Microsoft Defender for Endpoint �������ϴ�����Թ��� 1 �ļ�⡣

�˹����ᴴ��һ��������ʱ���е�ע����  
```Command
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "SOC Test" /t REG_SZ /F /D "C:\temp\startup.bat"
```

1. �� Azure Sentinel �Ż��У��ӡ����桱����ѡ�� **����־��**��

2. ������Ҫ�鿴�洢���ݵ�λ�á�ԭ������ո�ִ���˹�����  

    ����־ʱ�䷶Χ����Ϊ����ȥ 24 Сʱ����

3. �������� KQL ��䣺

```KQL
search "temp\\startup.bat"
```

4. ��� 3 ����ͬ�ı���ʾ�����
    DeviceProcessEvents
    DeviceRegistryEvents
    Event

    �豸*������ Defender for Endpoint������������ - Microsoft 365 Defender����  �¼�����������������ȫ�¼��� 

    ���ǽ���������������ͬԴ��Sysmon �� Defender for Endpoint�������ݣ�  ���������Ҫ��������֮������ϵ� KQL ��䡣  ���ε���ʱ���㽫�ֱ�鿴ÿ�����ݡ�

5. �˼�⽫�ص��ע���� Defender for Endpoint �����ݡ�  �������� KQL ��䣺

```KQL
search in (Device*) "temp\\startup.bat"
```

6. DeviceRegistryEvents ���е������Ѿ��淶�������ڽ��в�ѯ��  չ�����пɲ鿴���¼��ص������С�

7. ͨ����в�鱨�������˽⵽��в����������ʹ�� reg.exe ���ע����  Ŀ¼Ϊ c:\temp���ɽ� startup.bat ��Ϊ�������ơ�  ����� KQL ��䣺

```KQL

DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "reg.exe"
| where RegistryValueData startswith "c:\\temp"


```

�����������������  

8. ����ؾ����ܶ���ṩ���ھ����������ģ�Ϊ��ȫ��Ӫ���ķ���ʦ�ṩ�����������ͶӰ�ڵ����ϵͼ��ʹ�õ�ʵ�塣�������²�ѯ��

```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName == "reg.exe"
| where RegistryValueData startswith "c:\\temp"
| extend timestamp = TimeGenerated, HostCustomEntity = DeviceName, AccountCustomEntity = InitiatingProcessAccountName


```

   ![��Ļ��ͼ](../Media/SC200_sysmon_query2.png)

9.  ������׼�����˼������ڰ�����ѯ����־�����У�ѡ���������е� **��+ �½���������**��  Ȼ��ѡ�� **������ Azure Sentinel ������**��

10. ����������������򵼡�  �ڡ����桱ѡ��У����룺


    ���ƣ�D4E Startup RegKey

    ˵����c:\temp �е� D4E Startup Regkey

    ���ԣ� ������

    �����ԣ���

11. ѡ�� **����һ��: ���ù����߼� >��** ��ť��

12. �ڡ����ù����߼���ѡ��ϣ�Ӧ��������� **�������ѯ��**��

13. ���ڲ�ѯ�ƻ������������

- ���в�ѯ��ʱ������5 ����
- �鿴�����õ����ݣ�1 ��

**��ע**�⣬�����������ͬһ���������˶���¼���  ������ʵ���ҾͿ�ʹ����Щ������

14. ������ѡ���ΪĬ��ֵ��  ѡ�� **����һ��: �¼����� >��**��

15. ���ڡ��¼����á������������ 

- �¼����ã�������
- �������飺����

ѡ�� **����һ��: �Զ���Ӧ >��**��

16. ���ڡ��Զ���Ӧ��ѡ������������

- ѡ��PostMessageTeams-OnAlert����
- ѡ�� **����һ��: �鿴��**��

17. �ڡ��鿴 + ������ѡ��ϣ�ѡ�� **��������**��

### ���� 3�� ʹ�� SecurityEvent ��⹥�� 2

�ڴ������У��㽫�ڰ�װ�˰�ȫ�¼��������� Sysmon �������ϴ�����Թ��� 2 �ļ�⡣

�˹����ᴴ��һ�����û���������ӵ����ع���Ա��
```Command
net user theusernametoadd /add
net user theusernametoadd ThePassword1!
net localgroup administrators theusernametoadd /add
```

1. �� Azure Sentinel �Ż��ġ����桱����ѡ�� **����־��**��

2. ������Ҫ�鿴�洢���ݵ�λ�á�ԭ������ո�ִ���˹�����  

    ����־ʱ�䷶Χ����Ϊ����ȥ 24 Сʱ����

3. �������� KQL ��䣺

```KQL
search "administrators"
```

4. �����ʾ���±�����ݣ�
    Event
    SecurityEvent

5. ��һ������Դ�� SecurityEvent�����ڵ��� Windows ʹ���ĸ��¼� ID ��ȷ����������Ȩ����ӳ�Ա��  ���ǽ��鿴���� EventID ���¼���

4732 - һλ��Ա����ӵ������˰�ȫ�����ı����顣

�������½ű���

```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"

```

6. չ�����пɲ鿴���¼��ص������С�  ����Ҫ���ҵ��û���δ��ʾ��  ��������δ�洢���û������洢���ǰ�ȫ��ʶ�� (SID)��  ���� KQL ������ƥ�� SID�����������ӵ�����Ա��� TargetUserName��


```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"
| extend Acct = MemberSid, MachId = SourceComputerId 
| join kind=leftouter (
     SecurityEvent 
     | summarize count() by TargetSid, SourceComputerId, TargetUserName
     | project Acct1 = TargetSid, MachId1 = SourceComputerId, UserName1 = TargetUserName
) on $left.MachId == $right.MachId1, $left.Acct == $right.Acct1 

```
�����������������  

   ![��Ļ��ͼ](../Media/SC200_sysmon_attack3.png)

**��ע:** ʵ����ʹ�õ����ݼ���С����˸� KQL ���ܲ��᷵��Ԥ�ڽ����

7. ����ؾ����ܶ���ṩ���ھ����������ģ�Ϊ��ȫ��Ӫ����ʦ�ṩ�����������ͶӰ�ڵ����ϵͼ��ʹ�õ�ʵ�塣  �������²�ѯ��


```KQL
SecurityEvent
| where EventID == "4732"
| where TargetAccount == "Builtin\\Administrators"
| extend Acct = MemberSid, MachId = SourceComputerId 
| join kind=leftouter (
     SecurityEvent 
     | summarize count() by TargetSid, SourceComputerId, TargetUserName
     | project Acct1 = TargetSid, MachId1 = SourceComputerId, UserName1 = TargetUserName
) on $left.MachId == $right.MachId1, $left.Acct == $right.Acct1 
| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = UserName1

```

8. ������׼�����˼������ڰ����ò�ѯ����־�����У�ѡ���������е� **��+ �½���������**��Ȼ��ѡ�� **������ Azure Sentinel ������**��

9. ����������������򵼡�  �ڡ����桱ѡ��У����룺

- ���ƣ�SecurityEvents ���ع���Ա�û���Ӳ��� 
- ������SecurityEvents ���ع���Ա�û���Ӳ��� 
- ���ԣ���Ȩ����
- �����ԣ���

ѡ�� **����һ��: ���ù����߼� >��** ��ť��

10. �ڡ����ù����߼���ѡ��ϣ�Ӧ��������ˡ������ѯ��ӳ��ʵ�塱��

11. ���ڡ���ѯ�ƻ��������������

- ���в�ѯ��ʱ������5 ����
- �鿴�����õ����ݣ�1 ��

**��ע**�⣬�����������ͬһ���������˶���¼���  ������ʵ���ҾͿ�ʹ����Щ������

12. ������ѡ���ΪĬ��ֵ��  ѡ�� **����һ��: �¼����� >��**��

13. ���ڡ��¼����á������������ 

- �¼����ã�������
- �������飺����
- ѡ�� **����һ��: �Զ���Ӧ >��**

14. ���ڡ��Զ���Ӧ��ѡ������������

- ѡ�� **��PostMessageTeams-OnAlert��**��
- ѡ�� **����һ��: �鿴 >����ť**��

15. �ڡ��鿴��ѡ��У�ѡ�� **��������**��

## ת����ϰ 7
