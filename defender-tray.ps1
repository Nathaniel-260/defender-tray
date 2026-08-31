<#
    Defender Tray — חיווי ומתג להגנה בזמן אמת של Microsoft Defender.
    אייקון במגש המערכת: ירוק = מוגן, אדום = כבוי, אפור = לא זמין.
#>

# CheckOnly — בונה הכל, מדפיס את המצב ויוצא. לאבחון מהטרמינל, בלי הרמת הרשאות.
param([switch]$CheckOnly)

# --- הרשאות מנהל: נדרשות לשינוי המצב, לא לקריאתו ---
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $CheckOnly -and
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
            '-File', ('"{0}"' -f $PSCommandPath))
    } catch { }
    exit
}

# --- מופע יחיד (בדיקה אינה תופסת את הנעילה, כדי שתעבוד גם כשהכלי רץ) ---
$mutex = $null
if (-not $CheckOnly) {
    $isNewInstance = $false
    $mutex = New-Object Threading.Mutex($true, 'Local\DefenderTray', [ref]$isNewInstance)
    if (-not $isNewInstance) { exit }
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# הסתרת חלון הקונסולה שנפתח מאחור
$win32 = Add-Type -Name Win32 -Namespace DefenderTray -PassThru -MemberDefinition @'
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] public static extern bool SetProcessWorkingSetSize(
        IntPtr handle, IntPtr min, IntPtr max);
    [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr hIcon);
'@
$null = $win32::ShowWindow($win32::GetConsoleWindow(), 0)

# PowerShell מחזיק working set גדול בהרבה ממה שכלי מגש צריך; -1 מבקש מהמערכת לגזום אותו
function Compress-Memory {
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    $null = $win32::SetProcessWorkingSetSize($win32::GetCurrentProcess(), [IntPtr](-1), [IntPtr](-1))
}

[Windows.Forms.Application]::EnableVisualStyles()

# יומן דק — בלי זה אי אפשר לדעת למה כלי רקע נעלם מהמגש
$logPath = Join-Path (Split-Path $PSCommandPath) 'defender-tray.log'
function Write-Log {
    param([string]$Message)
    try {
        '{0:yyyy-MM-dd HH:mm:ss}  pid {1,-6} {2}' -f (Get-Date), $PID, $Message |
        Add-Content -Path $logPath -Encoding UTF8 -ErrorAction Stop
    } catch { }
}

# ---------------------------------------------------------------- אייקונים

function New-ShieldIcon {
    param([Drawing.Color]$Fill)

    $bitmap = New-Object Drawing.Bitmap 32, 32
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = 'AntiAlias'

    $shield = New-Object Drawing.Drawing2D.GraphicsPath
    $shield.AddPolygon([Drawing.Point[]]@(
        (New-Object Drawing.Point 16, 1), (New-Object Drawing.Point 30, 7),
        (New-Object Drawing.Point 30, 16), (New-Object Drawing.Point 16, 31),
        (New-Object Drawing.Point 2, 16), (New-Object Drawing.Point 2, 7)))

    $brush = New-Object Drawing.SolidBrush $Fill
    $pen = New-Object Drawing.Pen ([Drawing.Color]::FromArgb(230, 255, 255, 255)), 2.5
    $graphics.FillPath($brush, $shield)
    $graphics.DrawPath($pen, $shield)

    $brush.Dispose(); $pen.Dispose(); $shield.Dispose(); $graphics.Dispose()

    # FromHandle אינו נעשה הבעלים של ה-HICON — בלי Clone ואז DestroyIcon הידית דולפת
    $handle = $bitmap.GetHicon()
    $temp = [Drawing.Icon]::FromHandle($handle)
    $icon = $temp.Clone()
    $temp.Dispose()
    $null = $win32::DestroyIcon($handle)
    $bitmap.Dispose()
    return $icon
}

$icons = @{
    On      = New-ShieldIcon ([Drawing.Color]::FromArgb(16, 124, 16))
    Off     = New-ShieldIcon ([Drawing.Color]::FromArgb(196, 43, 28))
    Unknown = New-ShieldIcon ([Drawing.Color]::FromArgb(138, 136, 134))
}

# ---------------------------------------------------------------- קריאת מצב

# SecurityCenter2 עונה בסדר גודל מהר יותר מהספק של Defender, ומשמש רק כגלאי שינוי:
# כשהערך זז — קוראים את המצב האמיתי. כך הרענון התכוף כמעט לא עולה דבר.
function Get-StateSignature {
    try {
        $products = @(Get-CimInstance -Namespace root/SecurityCenter2 `
                -ClassName AntiVirusProduct -OperationTimeoutSec 30 -ErrorAction Stop)
        return ($products | ForEach-Object { $_.productState }) -join ','
    } catch { return $null }
}

function Get-DefenderState {
    try {
        # ספק ה-WMI של Defender איטי ולעתים נתקע; בלי תקרה, שאילתה תקועה מקפיאה את המגש לצמיתות
        $status = Get-CimInstance -Namespace root/Microsoft/Windows/Defender `
            -ClassName MSFT_MpComputerStatus -OperationTimeoutSec 30 -ErrorAction Stop
        return [pscustomobject]@{
            RealTime = [bool]$status.RealTimeProtectionEnabled
            Tampered = [bool]$status.IsTamperProtected
        }
    } catch { return $null }
}

# ---------------------------------------------------------------- מגש המערכת

$menu = New-Object Windows.Forms.ContextMenuStrip
$menu.RightToLeft = 'Yes'
$menu.ShowImageMargin = $false

$statusItem = $menu.Items.Add('בודק...')
$statusItem.Enabled = $false
$tamperItem = $menu.Items.Add('הגנה מפני טיפול שלא כדין חוסמת את המתג')
$tamperItem.Enabled = $false
$tamperItem.Visible = $false
$toggleItem = $menu.Items.Add('...')
$null = $menu.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
$securityItem = $menu.Items.Add('פתח את הגדרות ההגנה')
$startupItem = $menu.Items.Add('הפעלה עם ההתחברות')
$null = $menu.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
$exitItem = $menu.Items.Add('יציאה')

$tray = New-Object Windows.Forms.NotifyIcon
$tray.Icon = $icons.Unknown
$tray.Text = 'בודק את מצב Defender...'
$tray.ContextMenuStrip = $menu
$tray.Visible = $true

$script:realTime = $null
$script:tampered = $false
$script:signature = $null
$script:pendingTarget = $null
$script:pendingUntil = [datetime]::MinValue

function Update-Tray {
    $state = Get-DefenderState
    $script:signature = Get-StateSignature

    if ($null -eq $state) {
        $script:realTime = $null
        $script:tampered = $false
        $tray.Icon = $icons.Unknown
        $label = 'מצב ההגנה אינו זמין'
        $toggleItem.Text = 'אין גישה ל-Defender'
        $toggleItem.Enabled = $false
    } else {
        $script:realTime = $state.RealTime
        $script:tampered = $state.Tampered
        $toggleItem.Enabled = $true
        if ($state.RealTime) {
            $tray.Icon = $icons.On
            $label = 'הגנה בזמן אמת: פעילה'
            $toggleItem.Text = 'כבה הגנה בזמן אמת'
        } else {
            $tray.Icon = $icons.Off
            $label = 'הגנה בזמן אמת: כבויה'
            $toggleItem.Text = 'הפעל הגנה בזמן אמת'
        }
    }

    $statusItem.Text = $label
    $tamperItem.Visible = $script:tampered
    if ($script:tampered) { $label += ' (הגנה מפני טיפול שלא כדין פעילה)' }
    $tray.Text = if ($label.Length -gt 62) { $label.Substring(0, 59) + '...' } else { $label }
}

function Show-Warning {
    param([string]$Message)
    $rtl = [Windows.Forms.MessageBoxOptions]::RtlReading -bor `
        [Windows.Forms.MessageBoxOptions]::RightAlign
    $null = [Windows.Forms.MessageBox]::Show($Message, 'מתג Defender',
        [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Warning,
        [Windows.Forms.MessageBoxDefaultButton]::Button1, $rtl)
}

function Invoke-Toggle {
    $target = -not $script:realTime
    try {
        Set-MpPreference -DisableRealtimeMonitoring (-not $target) -ErrorAction Stop
    } catch {
        $failure = $_.Exception.Message
        Write-Log ('המתג נכשל: ' + $failure)
        # Tamper Protection חוסמת את Set-MpPreference בשני הכיוונים, גם בהדלקה
        if ($script:tampered) {
            Show-Warning ("'הגנה מפני טיפול שלא כדין' מופעלת, והיא חוסמת כל שינוי של " +
                "ההגנה בזמן אמת מתוך סקריפט — גם הדלקה.`n`nכדי לאפשר את המתג, כבה אותה ב:`n" +
                "אבטחת Windows ← הגנה מפני וירוסים ואיומים ← ניהול הגדרות ← הגנה מפני טיפול שלא כדין")
        } else {
            Show-Warning ("שינוי מצב ההגנה נכשל:`n`n" + $failure)
        }
        return
    }

    # Defender מחיל את השינוי באיחור של עד דקה; בדיקה מיידית תמיד תיראה ככישלון
    $script:pendingTarget = $target
    $script:pendingUntil = (Get-Date).AddMinutes(3)
    Write-Log ('נשלחה בקשת {0}' -f $(if ($target) { 'הפעלה' } else { 'כיבוי' }))
    $tray.ShowBalloonTip(5000, 'מתג Defender',
        'הבקשה נשלחה. Defender מחיל את השינוי תוך עד דקה.',
        [Windows.Forms.ToolTipIcon]::Info)
}

# ---------------------------------------------------------------- הפעלה בהתחברות

$taskName = 'DefenderTray'

function Test-StartupTask {
    $null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
}

function Set-StartupTask {
    param([bool]$Enabled)
    if (-not $Enabled) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        return
    }
    # RunLevel Highest — כך הכלי עולה מורם בלי בקשת UAC בכל התחברות
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $PSCommandPath)
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    $null = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Settings $settings -User ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME) `
        -RunLevel Highest -Force
}

# ---------------------------------------------------------------- אירועים

# אין כאן שאילתות: הטיימר כבר מחזיק מצב עדכני, וכל שאילתה כאן מעכבת את פתיחת התפריט בשניות

$toggleItem.add_Click({ Invoke-Toggle })

$securityItem.add_Click({
        Start-Process 'windowsdefender://threatsettings' -ErrorAction SilentlyContinue
    })

$startupItem.add_Click({
        # Get-ScheduledTask איטי מאוד; המשימה משתנה רק מכאן, אז הסימון הוא מקור האמת
        $enable = -not $startupItem.Checked
        try {
            Set-StartupTask $enable
            $startupItem.Checked = $enable
            Write-Log ('הפעלה עם ההתחברות: ' + $(if ($enable) { 'נרשמה' } else { 'בוטלה' }))
        } catch {
            Show-Warning ('לא ניתן לעדכן את ההפעלה האוטומטית:' + "`n" + $_.Exception.Message)
        }
    })

# לחיצה שמאלית בודדת פותחת את התפריט, כמו אייקוני מגש רבים
$tray.add_MouseClick({
        if ($_.Button -eq [Windows.Forms.MouseButtons]::Left) {
            $show = $tray.GetType().GetMethod('ShowContextMenu',
                [Reflection.BindingFlags]'Instance, NonPublic')
            $show.Invoke($tray, $null)
        }
    })

$script:tick = 0
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 3000
$timer.add_Tick({
        $waiting = $null -ne $script:pendingTarget
        # רענון מלא מדי דקה: מצב ההגנה מפני טיפול אינו משתקף בחתימה המהירה
        $periodic = $script:tick % 20 -eq 19
        if ($waiting -or $periodic -or (Get-StateSignature) -ne $script:signature) { Update-Tray }

        if ($waiting) {
            if ($script:realTime -eq $script:pendingTarget) {
                $script:pendingTarget = $null
                $done = if ($script:realTime) { 'ההגנה בזמן אמת הופעלה' } else { 'ההגנה בזמן אמת כובתה' }
                Write-Log $done
                $tray.ShowBalloonTip(4000, 'מתג Defender', $done, [Windows.Forms.ToolTipIcon]::Info)
            } elseif ((Get-Date) -gt $script:pendingUntil) {
                $script:pendingTarget = $null
                Write-Log 'הבקשה לא נקלטה בתוך שלוש דקות'
                Show-Warning ('מצב ההגנה לא השתנה גם אחרי שלוש דקות. ייתכן שמדיניות ארגונית ' +
                    'או תוכנת אבטחה אחרת חוסמת אותו.')
            }
        }

        $script:tick++
        if ($script:tick % 20 -eq 0) { Compress-Memory }
    })

$appContext = New-Object Windows.Forms.ApplicationContext

$exitItem.add_Click({
        Write-Log 'יציאה מהתפריט'
        $timer.Stop()
        $tray.Visible = $false
        $tray.Dispose()
        $appContext.ExitThread()
    })

Update-Tray

if ($CheckOnly) {
    'RealTime={0}  Tampered={1}  Tooltip="{2}"  Toggle="{3}"  Startup={4}' -f
    $script:realTime, $script:tampered, $tray.Text, $toggleItem.Text, (Test-StartupTask)
    $tray.Visible = $false
    $tray.Dispose()
    exit
}

$startupItem.Checked = Test-StartupTask
$timer.Start()
Compress-Memory
Write-Log ('עלה. הגנה בזמן אמת: {0}' -f $(if ($script:realTime) { 'פעילה' } else { 'כבויה' }))

try {
    [Windows.Forms.Application]::Run($appContext)
    Write-Log 'הסתיים כרגיל'
} catch {
    Write-Log ('קרס: ' + $_.Exception.Message)
}

if ($mutex) {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
