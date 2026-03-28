[CmdletBinding()]
param(
    [switch]$full,
    [switch]$region,
    [switch]$window,
    [int]$delay = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class NativeMethods
{
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }
}
"@

$SW_RESTORE = 9
$SW_MAXIMIZE = 3
$SW_MINIMIZE = 6

$Script:SettingsPath = Join-Path -Path $PSScriptRoot -ChildPath 'screenshot_settings.json'
$Script:History = New-Object System.Collections.ArrayList
$Script:LastSelectedWindow = $null

function Get-DefaultSettings {
    return [ordered]@{
        AutoSaveFolder   = ''
        DefaultFormat    = 'PNG'
        CopyToClipboard  = $true
        SilentMode       = $false
        DelaySeconds     = 0
        FileNameTemplate = 'screenshot_YYYYMMDD_HHMMSS'
        QuickCopyOnly    = $false
        MonitorIndex     = 0
        HistoryLimit     = 20
    }
}

function Load-Settings {
    $defaults = Get-DefaultSettings
    if (-not (Test-Path $Script:SettingsPath)) { return $defaults }

    try {
        $json = Get-Content -Path $Script:SettingsPath -Raw -Encoding UTF8
        $parsed = ConvertFrom-Json -InputObject $json
        foreach ($k in $defaults.Keys) {
            if ($null -ne $parsed.$k) {
                $defaults[$k] = $parsed.$k
            }
        }
    } catch {
        # ignore and use defaults
    }
    return $defaults
}

function Save-Settings([hashtable]$settings) {
    try {
        ($settings | ConvertTo-Json -Depth 5) | Set-Content -Path $Script:SettingsPath -Encoding UTF8
    } catch {
        # ignore in WinPE read-only scenarios
    }
}

$Script:Settings = Load-Settings
if ($delay -gt 0) { $Script:Settings.DelaySeconds = $delay }

function Show-Info([string]$message) {
    if (-not $Script:Settings.SilentMode) {
        [System.Windows.Forms.MessageBox]::Show($message, 'Screenshot Tool', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    }
}

function Show-Error([string]$message) {
    if (-not $Script:Settings.SilentMode) {
        [System.Windows.Forms.MessageBox]::Show($message, 'Screenshot Tool', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

function New-FileNameFromTemplate([string]$template) {
    if ([string]::IsNullOrWhiteSpace($template)) {
        $template = 'screenshot_YYYYMMDD_HHMMSS'
    }
    $now = Get-Date
    $name = $template
    $name = $name.Replace('YYYY', $now.ToString('yyyy'))
    $name = $name.Replace('MM', $now.ToString('MM'))
    $name = $name.Replace('DD', $now.ToString('dd'))
    $name = $name.Replace('HH', $now.ToString('HH'))
    $name = $name.Replace('mm', $now.ToString('mm'))
    $name = $name.Replace('SS', $now.ToString('ss'))
    $invalid = [IO.Path]::GetInvalidFileNameChars()
    foreach ($ch in $invalid) { $name = $name.Replace($ch, '_') }
    return $name
}

function Get-ImageFormatInfo([string]$fmt) {
    switch ($fmt.ToUpperInvariant()) {
        'PNG'  { return @{ Ext = 'png'; Gdi = [System.Drawing.Imaging.ImageFormat]::Png } }
        'JPG'  { return @{ Ext = 'jpg'; Gdi = [System.Drawing.Imaging.ImageFormat]::Jpeg } }
        'JPEG' { return @{ Ext = 'jpg'; Gdi = [System.Drawing.Imaging.ImageFormat]::Jpeg } }
        'BMP'  { return @{ Ext = 'bmp'; Gdi = [System.Drawing.Imaging.ImageFormat]::Bmp } }
        'TIFF' { return @{ Ext = 'tiff'; Gdi = [System.Drawing.Imaging.ImageFormat]::Tiff } }
        default { return @{ Ext = 'png'; Gdi = [System.Drawing.Imaging.ImageFormat]::Png } }
    }
}

function Get-SelectedMonitor {
    $screens = [System.Windows.Forms.Screen]::AllScreens
    if ($screens.Count -eq 0) { return [System.Windows.Forms.Screen]::PrimaryScreen }
    $idx = [int]$Script:Settings.MonitorIndex
    if ($idx -lt 0 -or $idx -ge $screens.Count) { $idx = 0 }
    return $screens[$idx]
}

function Capture-Bounds([System.Drawing.Rectangle]$bounds) {
    if ($bounds.Width -le 0 -or $bounds.Height -le 0) { return $null }
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    } finally {
        $g.Dispose()
    }
    return $bmp
}

function Get-WindowList {
    $items = New-Object System.Collections.Generic.List[object]
    $callback = [NativeMethods+EnumWindowsProc]{
        param([IntPtr]$hWnd, [IntPtr]$lParam)
        if (-not [NativeMethods]::IsWindowVisible($hWnd)) { return $true }
        $len = [NativeMethods]::GetWindowTextLength($hWnd)
        if ($len -le 0) { return $true }
        $sb = New-Object System.Text.StringBuilder ($len + 1)
        [void][NativeMethods]::GetWindowText($hWnd, $sb, $sb.Capacity)
        $title = $sb.ToString().Trim()
        if ([string]::IsNullOrWhiteSpace($title)) { return $true }

        $r = New-Object NativeMethods+RECT
        if (-not [NativeMethods]::GetWindowRect($hWnd, [ref]$r)) { return $true }
        $w = $r.Right - $r.Left
        $h = $r.Bottom - $r.Top
        if ($w -lt 50 -or $h -lt 50) { return $true }

        $items.Add([pscustomobject]@{
            Handle = $hWnd
            Title  = $title
            Bounds = [System.Drawing.Rectangle]::FromLTRB($r.Left, $r.Top, $r.Right, $r.Bottom)
        })
        return $true
    }
    [void][NativeMethods]::EnumWindows($callback, [IntPtr]::Zero)
    return $items | Sort-Object Title
}

function Select-Region([System.Windows.Forms.Screen]$screen) {
    $overlay = New-Object System.Windows.Forms.Form
    $overlay.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
    $overlay.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
    $overlay.Bounds = $screen.Bounds
    $overlay.TopMost = $true
    $overlay.BackColor = [System.Drawing.Color]::Black
    $overlay.Opacity = 0.25
    $overlay.ShowInTaskbar = $false
    $overlay.Cursor = [System.Windows.Forms.Cursors]::Cross
    $overlay.KeyPreview = $true

    $hint = New-Object System.Windows.Forms.Label
    $hint.Text = 'Drag to select region. Press ESC to cancel.'
    $hint.AutoSize = $true
    $hint.BackColor = [System.Drawing.Color]::FromArgb(220, 255, 255, 210)
    $hint.ForeColor = [System.Drawing.Color]::Black
    $hint.Location = New-Object System.Drawing.Point 15, 15
    $overlay.Controls.Add($hint)

    $selectionBorder = New-Object System.Windows.Forms.Panel
    $selectionBorder.Visible = $false
    $selectionBorder.BackColor = [System.Drawing.Color]::Transparent
    $selectionBorder.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $overlay.Controls.Add($selectionBorder)

    $dragging = $false
    $start = [System.Drawing.Point]::Empty
    $selectedRect = [System.Drawing.Rectangle]::Empty

    $overlay.Add_KeyDown({
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
            $overlay.Tag = $null
            $overlay.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $overlay.Close()
        }
    })

    $overlay.Add_MouseDown({
        if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
            $dragging = $true
            $start = $_.Location
            $selectionBorder.Visible = $true
            $selectionBorder.Bounds = New-Object System.Drawing.Rectangle $start.X, $start.Y, 1, 1
        }
    })

    $overlay.Add_MouseMove({
        if ($dragging) {
            $x = [Math]::Min($start.X, $_.X)
            $y = [Math]::Min($start.Y, $_.Y)
            $w = [Math]::Abs($_.X - $start.X)
            $h = [Math]::Abs($_.Y - $start.Y)
            $selectionBorder.Bounds = New-Object System.Drawing.Rectangle $x, $y, $w, $h
        }
    })

    $overlay.Add_MouseUp({
        if ($dragging) {
            $dragging = $false
            $rect = $selectionBorder.Bounds
            if ($rect.Width -gt 5 -and $rect.Height -gt 5) {
                $selectedRect = New-Object System.Drawing.Rectangle ($rect.X + $screen.Bounds.X), ($rect.Y + $screen.Bounds.Y), $rect.Width, $rect.Height
                $overlay.Tag = $selectedRect
                $overlay.DialogResult = [System.Windows.Forms.DialogResult]::OK
            } else {
                $overlay.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            }
            $overlay.Close()
        }
    })

    $result = $overlay.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK -and $overlay.Tag) {
        return [System.Drawing.Rectangle]$overlay.Tag
    }
    return $null
}

function Save-OrCopyBitmap([System.Drawing.Bitmap]$bmp) {
    if ($null -eq $bmp) { return $null }

    if ($Script:Settings.CopyToClipboard -or $Script:Settings.QuickCopyOnly) {
        try { [System.Windows.Forms.Clipboard]::SetImage($bmp) } catch {}
    }

    if ($Script:Settings.QuickCopyOnly) {
        Add-HistoryEntry -bitmap $bmp -path '[Clipboard only]'
        Show-Info 'Screenshot copied to clipboard.'
        return $null
    }

    $fmtInfo = Get-ImageFormatInfo $Script:Settings.DefaultFormat
    $baseName = New-FileNameFromTemplate $Script:Settings.FileNameTemplate
    $fileName = "$baseName.$($fmtInfo.Ext)"

    $targetPath = $null
    if (-not [string]::IsNullOrWhiteSpace($Script:Settings.AutoSaveFolder)) {
        if (-not (Test-Path $Script:Settings.AutoSaveFolder)) {
            try {
                New-Item -Path $Script:Settings.AutoSaveFolder -ItemType Directory -Force | Out-Null
            } catch {
                Show-Error "Cannot create folder: $($Script:Settings.AutoSaveFolder)"
                return $null
            }
        }
        $targetPath = Join-Path $Script:Settings.AutoSaveFolder $fileName
        $i = 1
        while (Test-Path $targetPath) {
            $targetPath = Join-Path $Script:Settings.AutoSaveFolder ("{0}_{1}.{2}" -f $baseName, $i, $fmtInfo.Ext)
            $i++
        }
    } else {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Title = 'Save Screenshot'
        $sfd.Filter = 'PNG (*.png)|*.png|JPG (*.jpg)|*.jpg|BMP (*.bmp)|*.bmp|TIFF (*.tiff)|*.tiff'
        switch ($fmtInfo.Ext) {
            'png'  { $sfd.FilterIndex = 1 }
            'jpg'  { $sfd.FilterIndex = 2 }
            'bmp'  { $sfd.FilterIndex = 3 }
            'tiff' { $sfd.FilterIndex = 4 }
        }
        $sfd.FileName = $fileName
        if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            return $null
        }
        $targetPath = $sfd.FileName
        $ext = [IO.Path]::GetExtension($targetPath).TrimStart('.').ToUpperInvariant()
        if ($ext) { $fmtInfo = Get-ImageFormatInfo $ext }
    }

    try {
        $bmp.Save($targetPath, $fmtInfo.Gdi)
        Add-HistoryEntry -bitmap $bmp -path $targetPath
        if (-not $Script:Settings.SilentMode) {
            Show-Info "Saved: $targetPath"
        }
        return $targetPath
    } catch {
        Show-Error "Save failed: $($_.Exception.Message)"
        return $null
    }
}

function Add-HistoryEntry {
    param(
        [System.Drawing.Bitmap]$bitmap,
        [string]$path
    )

    if ($null -eq $bitmap) { return }
    $thumb = New-Object System.Drawing.Bitmap 180, 100
    $g = [System.Drawing.Graphics]::FromImage($thumb)
    try {
        $g.Clear([System.Drawing.Color]::Black)
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $ratio = [Math]::Min(180 / $bitmap.Width, 100 / $bitmap.Height)
        $w = [int]($bitmap.Width * $ratio)
        $h = [int]($bitmap.Height * $ratio)
        $x = [int]((180 - $w) / 2)
        $y = [int]((100 - $h) / 2)
        $g.DrawImage($bitmap, $x, $y, $w, $h)
    } finally {
        $g.Dispose()
    }

    $entry = [pscustomobject]@{
        Time    = Get-Date
        Path    = $path
        Width   = $bitmap.Width
        Height  = $bitmap.Height
        Thumb   = $thumb
    }

    [void]$Script:History.Insert(0, $entry)
    while ($Script:History.Count -gt [int]$Script:Settings.HistoryLimit) {
        $last = $Script:History[$Script:History.Count - 1]
        if ($last.Thumb) { $last.Thumb.Dispose() }
        $Script:History.RemoveAt($Script:History.Count - 1)
    }

    Update-HistoryUi
}

$Script:HistoryListView = $null
$Script:HistoryImageList = $null

function Update-HistoryUi {
    if ($null -eq $Script:HistoryListView -or $null -eq $Script:HistoryImageList) { return }

    $Script:HistoryListView.BeginUpdate()
    try {
        $Script:HistoryImageList.Images.Clear()
        $Script:HistoryListView.Items.Clear()

        for ($i = 0; $i -lt $Script:History.Count; $i++) {
            $entry = $Script:History[$i]
            $Script:HistoryImageList.Images.Add("img$i", $entry.Thumb)
            $caption = "{0} ({1}x{2})" -f $entry.Time.ToString('yyyy-MM-dd HH:mm:ss'), $entry.Width, $entry.Height
            $item = New-Object System.Windows.Forms.ListViewItem($caption, "img$i")
            [void]$item.SubItems.Add($entry.Path)
            $item.ToolTipText = $entry.Path
            [void]$Script:HistoryListView.Items.Add($item)
        }
    } finally {
        $Script:HistoryListView.EndUpdate()
    }
}

function Invoke-DelayedAction([ScriptBlock]$action) {
    $sec = [int]$Script:Settings.DelaySeconds
    if ($sec -gt 0) { Start-Sleep -Seconds $sec }
    & $action
}

function Run-FullCapture {
    param([System.Windows.Forms.Form]$mainForm)

    $mainForm.Hide()
    Start-Sleep -Milliseconds 200
    try {
        Invoke-DelayedAction {
            $monitor = Get-SelectedMonitor
            $bmp = Capture-Bounds $monitor.Bounds
            if ($bmp) {
                try { [void](Save-OrCopyBitmap $bmp) } finally { $bmp.Dispose() }
            }
        }
    } finally {
        $mainForm.Show()
        $mainForm.Activate()
    }
}

function Run-RegionCapture {
    param([System.Windows.Forms.Form]$mainForm)

    $mainForm.Hide()
    Start-Sleep -Milliseconds 250
    try {
        Invoke-DelayedAction {
            $screen = Get-SelectedMonitor
            $rect = Select-Region $screen
            if ($rect) {
                $bmp = Capture-Bounds $rect
                if ($bmp) {
                    try { [void](Save-OrCopyBitmap $bmp) } finally { $bmp.Dispose() }
                }
            }
        }
    } finally {
        $mainForm.Show()
        $mainForm.Activate()
    }
}

function Run-WindowCapture {
    param([System.Windows.Forms.Form]$mainForm, [IntPtr]$hWnd)

    if ($hWnd -eq [IntPtr]::Zero) {
        Show-Error 'Please select a window first.'
        return
    }

    $mainForm.Hide()
    Start-Sleep -Milliseconds 250
    try {
        Invoke-DelayedAction {
            [void][NativeMethods]::ShowWindow($hWnd, $SW_RESTORE)
            Start-Sleep -Milliseconds 80
            [void][NativeMethods]::ShowWindow($hWnd, $SW_MAXIMIZE)
            [void][NativeMethods]::SetForegroundWindow($hWnd)
            Start-Sleep -Milliseconds 300

            $r = New-Object NativeMethods+RECT
            if (-not [NativeMethods]::GetWindowRect($hWnd, [ref]$r)) {
                Show-Error 'Cannot read window bounds.'
                return
            }
            $bounds = [System.Drawing.Rectangle]::FromLTRB($r.Left, $r.Top, $r.Right, $r.Bottom)
            $bmp = Capture-Bounds $bounds
            if ($bmp) {
                try { [void](Save-OrCopyBitmap $bmp) } finally { $bmp.Dispose() }
            }

            Start-Sleep -Milliseconds 120
            [void][NativeMethods]::ShowWindow($hWnd, $SW_MINIMIZE)
        }
    } finally {
        $mainForm.Show()
        $mainForm.Activate()
    }
}

function New-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'WinPE Screenshot Tool'
    $form.Width = 920
    $form.Height = 630
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.KeyPreview = $true

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = [System.Windows.Forms.DockStyle]::Fill

    # Full Screen tab
    $tabFull = New-Object System.Windows.Forms.TabPage
    $tabFull.Text = 'Full Screen'
    $btnFull = New-Object System.Windows.Forms.Button
    $btnFull.Text = 'Capture Full Screen (F1)'
    $btnFull.Width = 220
    $btnFull.Height = 36
    $btnFull.Location = New-Object System.Drawing.Point 20, 20
    $lblFull = New-Object System.Windows.Forms.Label
    $lblFull.Text = 'Captures the selected monitor.'
    $lblFull.AutoSize = $true
    $lblFull.Location = New-Object System.Drawing.Point 20, 70
    $tabFull.Controls.AddRange(@($btnFull, $lblFull))

    # Select Region tab
    $tabRegion = New-Object System.Windows.Forms.TabPage
    $tabRegion.Text = 'Select Region'
    $btnRegion = New-Object System.Windows.Forms.Button
    $btnRegion.Text = 'Capture Selected Region (F2)'
    $btnRegion.Width = 220
    $btnRegion.Height = 36
    $btnRegion.Location = New-Object System.Drawing.Point 20, 20
    $lblRegion = New-Object System.Windows.Forms.Label
    $lblRegion.Text = 'Drag mouse to select area. Press ESC to cancel.'
    $lblRegion.AutoSize = $true
    $lblRegion.Location = New-Object System.Drawing.Point 20, 70
    $tabRegion.Controls.AddRange(@($btnRegion, $lblRegion))

    # Window tab
    $tabWindow = New-Object System.Windows.Forms.TabPage
    $tabWindow.Text = 'Choose Window'
    $btnRefreshWin = New-Object System.Windows.Forms.Button
    $btnRefreshWin.Text = 'Refresh'
    $btnRefreshWin.Location = New-Object System.Drawing.Point 20, 18
    $btnRefreshWin.Width = 90
    $btnWindow = New-Object System.Windows.Forms.Button
    $btnWindow.Text = 'Capture Window (F3)'
    $btnWindow.Location = New-Object System.Drawing.Point 120, 18
    $btnWindow.Width = 170

    $listWindows = New-Object System.Windows.Forms.ListBox
    $listWindows.Location = New-Object System.Drawing.Point 20, 60
    $listWindows.Width = 840
    $listWindows.Height = 460
    $listWindows.DisplayMember = 'Title'

    $tabWindow.Controls.AddRange(@($btnRefreshWin, $btnWindow, $listWindows))

    # Settings tab
    $tabSettings = New-Object System.Windows.Forms.TabPage
    $tabSettings.Text = 'Settings'

    $y = 20
    $lblFolder = New-Object System.Windows.Forms.Label
    $lblFolder.Text = 'Auto-save folder:'
    $lblFolder.Location = New-Object System.Drawing.Point 20, $y
    $lblFolder.AutoSize = $true

    $txtFolder = New-Object System.Windows.Forms.TextBox
    $txtFolder.Location = New-Object System.Drawing.Point 160, ($y - 3)
    $txtFolder.Width = 570

    $btnBrowse = New-Object System.Windows.Forms.Button
    $btnBrowse.Text = 'Browse...'
    $btnBrowse.Location = New-Object System.Drawing.Point 740, ($y - 5)
    $btnBrowse.Width = 100

    $y += 40
    $lblFormat = New-Object System.Windows.Forms.Label
    $lblFormat.Text = 'Default format:'
    $lblFormat.Location = New-Object System.Drawing.Point 20, $y
    $lblFormat.AutoSize = $true
    $cmbFormat = New-Object System.Windows.Forms.ComboBox
    $cmbFormat.Location = New-Object System.Drawing.Point 160, ($y - 3)
    $cmbFormat.Width = 120
    $cmbFormat.DropDownStyle = 'DropDownList'
    [void]$cmbFormat.Items.AddRange(@('PNG','JPG','BMP','TIFF'))

    $y += 40
    $chkClipboard = New-Object System.Windows.Forms.CheckBox
    $chkClipboard.Text = 'Copy to Clipboard'
    $chkClipboard.Location = New-Object System.Drawing.Point 20, $y
    $chkClipboard.AutoSize = $true

    $chkSilent = New-Object System.Windows.Forms.CheckBox
    $chkSilent.Text = 'Silent Mode'
    $chkSilent.Location = New-Object System.Drawing.Point 220, $y
    $chkSilent.AutoSize = $true

    $chkQuickCopy = New-Object System.Windows.Forms.CheckBox
    $chkQuickCopy.Text = 'Quick copy only'
    $chkQuickCopy.Location = New-Object System.Drawing.Point 360, $y
    $chkQuickCopy.AutoSize = $true

    $y += 40
    $lblDelay = New-Object System.Windows.Forms.Label
    $lblDelay.Text = 'Delay (seconds):'
    $lblDelay.Location = New-Object System.Drawing.Point 20, $y
    $lblDelay.AutoSize = $true

    $numDelay = New-Object System.Windows.Forms.NumericUpDown
    $numDelay.Location = New-Object System.Drawing.Point 160, ($y - 3)
    $numDelay.Width = 80
    $numDelay.Minimum = 0
    $numDelay.Maximum = 60

    $lblMonitor = New-Object System.Windows.Forms.Label
    $lblMonitor.Text = 'Monitor:'
    $lblMonitor.Location = New-Object System.Drawing.Point 280, $y
    $lblMonitor.AutoSize = $true

    $cmbMonitor = New-Object System.Windows.Forms.ComboBox
    $cmbMonitor.Location = New-Object System.Drawing.Point 350, ($y - 3)
    $cmbMonitor.Width = 260
    $cmbMonitor.DropDownStyle = 'DropDownList'

    $y += 40
    $lblTemplate = New-Object System.Windows.Forms.Label
    $lblTemplate.Text = 'File name template:'
    $lblTemplate.Location = New-Object System.Drawing.Point 20, $y
    $lblTemplate.AutoSize = $true

    $txtTemplate = New-Object System.Windows.Forms.TextBox
    $txtTemplate.Location = New-Object System.Drawing.Point 160, ($y - 3)
    $txtTemplate.Width = 450

    $lblHist = New-Object System.Windows.Forms.Label
    $lblHist.Text = 'History limit:'
    $lblHist.Location = New-Object System.Drawing.Point 620, $y
    $lblHist.AutoSize = $true

    $numHist = New-Object System.Windows.Forms.NumericUpDown
    $numHist.Location = New-Object System.Drawing.Point 700, ($y - 3)
    $numHist.Width = 80
    $numHist.Minimum = 1
    $numHist.Maximum = 200

    $y += 50
    $btnSaveSettings = New-Object System.Windows.Forms.Button
    $btnSaveSettings.Text = 'Save Settings'
    $btnSaveSettings.Location = New-Object System.Drawing.Point 20, $y
    $btnSaveSettings.Width = 140

    $tabSettings.Controls.AddRange(@(
        $lblFolder, $txtFolder, $btnBrowse,
        $lblFormat, $cmbFormat,
        $chkClipboard, $chkSilent, $chkQuickCopy,
        $lblDelay, $numDelay, $lblMonitor, $cmbMonitor,
        $lblTemplate, $txtTemplate, $lblHist, $numHist,
        $btnSaveSettings
    ))

    # History tab
    $tabHistory = New-Object System.Windows.Forms.TabPage
    $tabHistory.Text = 'History'
    $Script:HistoryImageList = New-Object System.Windows.Forms.ImageList
    $Script:HistoryImageList.ImageSize = New-Object System.Drawing.Size 180, 100
    $Script:HistoryImageList.ColorDepth = [System.Windows.Forms.ColorDepth]::Depth32Bit

    $Script:HistoryListView = New-Object System.Windows.Forms.ListView
    $Script:HistoryListView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $Script:HistoryListView.LargeImageList = $Script:HistoryImageList
    $Script:HistoryListView.View = [System.Windows.Forms.View]::LargeIcon
    $Script:HistoryListView.MultiSelect = $false

    $tabHistory.Controls.Add($Script:HistoryListView)

    $tabs.TabPages.AddRange(@($tabFull, $tabRegion, $tabWindow, $tabSettings, $tabHistory))
    $form.Controls.Add($tabs)

    function Refresh-WindowList {
        $current = Get-WindowList
        $listWindows.Items.Clear()
        foreach ($w in $current) { [void]$listWindows.Items.Add($w) }
        if ($listWindows.Items.Count -gt 0) {
            $listWindows.SelectedIndex = 0
            $Script:LastSelectedWindow = $listWindows.SelectedItem
        }
    }

    function Load-SettingsToUi {
        $txtFolder.Text = [string]$Script:Settings.AutoSaveFolder
        $cmbFormat.SelectedItem = [string]$Script:Settings.DefaultFormat
        if (-not $cmbFormat.SelectedItem) { $cmbFormat.SelectedItem = 'PNG' }
        $chkClipboard.Checked = [bool]$Script:Settings.CopyToClipboard
        $chkSilent.Checked = [bool]$Script:Settings.SilentMode
        $chkQuickCopy.Checked = [bool]$Script:Settings.QuickCopyOnly
        $numDelay.Value = [decimal][Math]::Max(0, [Math]::Min(60, [int]$Script:Settings.DelaySeconds))
        $txtTemplate.Text = [string]$Script:Settings.FileNameTemplate
        $numHist.Value = [decimal][Math]::Max(1, [Math]::Min(200, [int]$Script:Settings.HistoryLimit))

        $cmbMonitor.Items.Clear()
        $screens = [System.Windows.Forms.Screen]::AllScreens
        for ($i = 0; $i -lt $screens.Count; $i++) {
            $b = $screens[$i].Bounds
            $primary = if ($screens[$i].Primary) { ' (Primary)' } else { '' }
            [void]$cmbMonitor.Items.Add("#$i: $($b.Width)x$($b.Height) at [$($b.X),$($b.Y)]$primary")
        }
        if ($cmbMonitor.Items.Count -eq 0) { [void]$cmbMonitor.Items.Add('#0: Primary') }
        $idx = [Math]::Max(0, [Math]::Min($cmbMonitor.Items.Count - 1, [int]$Script:Settings.MonitorIndex))
        $cmbMonitor.SelectedIndex = $idx
    }

    function Save-UiToSettings {
        $Script:Settings.AutoSaveFolder = $txtFolder.Text.Trim()
        $Script:Settings.DefaultFormat = [string]$cmbFormat.SelectedItem
        $Script:Settings.CopyToClipboard = $chkClipboard.Checked
        $Script:Settings.SilentMode = $chkSilent.Checked
        $Script:Settings.QuickCopyOnly = $chkQuickCopy.Checked
        $Script:Settings.DelaySeconds = [int]$numDelay.Value
        $Script:Settings.FileNameTemplate = $txtTemplate.Text.Trim()
        $Script:Settings.HistoryLimit = [int]$numHist.Value
        $Script:Settings.MonitorIndex = [int]$cmbMonitor.SelectedIndex
        Save-Settings $Script:Settings
    }

    $btnBrowse.Add_Click({
        $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
        $fbd.Description = 'Select auto-save folder'
        if ($fbd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $txtFolder.Text = $fbd.SelectedPath
        }
    })

    $btnSaveSettings.Add_Click({
        Save-UiToSettings
        Show-Info 'Settings saved.'
        Update-HistoryUi
    })

    $btnRefreshWin.Add_Click({ Refresh-WindowList })
    $listWindows.Add_SelectedIndexChanged({
        if ($listWindows.SelectedItem) {
            $Script:LastSelectedWindow = $listWindows.SelectedItem
        }
    })

    $btnFull.Add_Click({ Save-UiToSettings; Run-FullCapture $form })
    $btnRegion.Add_Click({ Save-UiToSettings; Run-RegionCapture $form })
    $btnWindow.Add_Click({
        Save-UiToSettings
        if ($listWindows.SelectedItem) { $Script:LastSelectedWindow = $listWindows.SelectedItem }
        if ($Script:LastSelectedWindow) {
            Run-WindowCapture -mainForm $form -hWnd $Script:LastSelectedWindow.Handle
        } else {
            Show-Error 'No window selected.'
        }
    })

    $Script:HistoryListView.Add_DoubleClick({
        if ($Script:HistoryListView.SelectedItems.Count -gt 0) {
            $index = $Script:HistoryListView.SelectedItems[0].Index
            if ($index -ge 0 -and $index -lt $Script:History.Count) {
                $entry = $Script:History[$index]
                if ($entry.Path -and $entry.Path -ne '[Clipboard only]' -and (Test-Path $entry.Path)) {
                    Start-Process -FilePath $entry.Path | Out-Null
                }
            }
        }
    })

    $form.Add_KeyDown({
        switch ($_.KeyCode) {
            ([System.Windows.Forms.Keys]::F1) { Save-UiToSettings; Run-FullCapture $form; $_.Handled = $true }
            ([System.Windows.Forms.Keys]::F2) { Save-UiToSettings; Run-RegionCapture $form; $_.Handled = $true }
            ([System.Windows.Forms.Keys]::F3) {
                Save-UiToSettings
                if ($Script:LastSelectedWindow) { Run-WindowCapture -mainForm $form -hWnd $Script:LastSelectedWindow.Handle }
                $_.Handled = $true
            }
        }
    })

    $form.Add_Shown({
        Load-SettingsToUi
        Refresh-WindowList
        Update-HistoryUi

        if ($full -or $region -or $window) {
            if ($full) { Run-FullCapture $form }
            elseif ($region) { Run-RegionCapture $form }
            elseif ($window -and $Script:LastSelectedWindow) { Run-WindowCapture -mainForm $form -hWnd $Script:LastSelectedWindow.Handle }
        }
    })

    $form.Add_FormClosing({
        Save-UiToSettings
        foreach ($e in $Script:History) {
            if ($e.Thumb) { $e.Thumb.Dispose() }
        }
    })

    return $form
}

$form = New-MainForm
[void][System.Windows.Forms.Application]::Run($form)
