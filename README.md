# WinPE Screenshot Tool

`WinPE-ScreenshotTool.ps1` is a single-file PowerShell WinForms utility for:

- Full-screen capture (selected monitor)
- Region capture (mouse selection)
- Window capture (choose window)
- Basic editor (draw/text)
- History with thumbnails
- Screen recording (MP4 via ffmpeg, or ZIP of PNG frames)

## Requirements

- Windows PowerShell with WinForms support
- .NET Framework (System.Windows.Forms, System.Drawing)
- Optional for MP4 export: `ffmpeg.exe`

## Where to download `ffmpeg.exe`

Use one of these official/safe sources:

1. **Official FFmpeg site** (project homepage):
   - https://ffmpeg.org/download.html
2. **Gyan.dev builds** (commonly used Windows builds):
   - https://www.gyan.dev/ffmpeg/builds/
3. **BtbN GitHub builds**:
   - https://github.com/BtbN/FFmpeg-Builds/releases

> For WinPE portability, the easiest way is to place `ffmpeg.exe` in the **same folder** as `WinPE-ScreenshotTool.ps1`.

The script searches `ffmpeg.exe` in this order:

1. Script folder (`$PSScriptRoot\\ffmpeg.exe`)
2. `C:\Windows\System32\ffmpeg.exe`
3. `PATH`

If ffmpeg is not found, MP4 export will fail with a clear message, and ZIP export remains available.

## Quick start

```powershell
powershell -ExecutionPolicy Bypass -File .\WinPE-ScreenshotTool.ps1
```

Command line options:

- `-full` : start with full-screen capture
- `-region` : start with region capture
- `-window` : start with window capture
- `-delay <seconds>` : capture delay

## Recording notes

- Open **Record Screen** tab
- Set FPS
- Start recording (or press `F4`)
- Stop recording and choose:
  - `.mp4` (requires ffmpeg)
  - `.zip` (PNG frames only, no ffmpeg needed)

## Hotkeys

- `F1` Full screen
- `F2` Region
- `F3` Window
- `F4` Start/Stop recording
- `ESC` Cancel region selection
