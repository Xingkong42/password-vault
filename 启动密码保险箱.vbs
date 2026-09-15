' 密码保险箱 —— 无控制台窗口启动脚本
' 双击本文件即可运行；把快捷方式放到桌面更方便。

Option Explicit

Dim shell, fso, baseDir, pythonw, python

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = baseDir

' 优先使用同目录虚拟环境里的解释器，其次使用系统 PATH 中的 pythonw
If fso.FileExists(baseDir & "\.venv\Scripts\pythonw.exe") Then
    pythonw = baseDir & "\.venv\Scripts\pythonw.exe"
    python = baseDir & "\.venv\Scripts\python.exe"
Else
    pythonw = "pythonw.exe"
    python = "python.exe"
End If

On Error Resume Next
shell.Run """" & pythonw & """ """ & baseDir & "\main.py""", 0, False
If Err.Number <> 0 Then
    Err.Clear
    ' 没有 pythonw 时退回 python（会带一个控制台窗口）
    shell.Run """" & python & """ """ & baseDir & "\main.py""", 1, False
End If
On Error GoTo 0
