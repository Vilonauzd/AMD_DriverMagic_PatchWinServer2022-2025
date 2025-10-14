# Deploy-TTS-DirectML.ps1
# Offline TTS on Windows Server with AMD GPU via PyTorch-DirectML

$ErrorActionPreference = "Stop"
$TTSRoot = "$env:ProgramData\OfflineTTS-DirectML"

Write-Host "🚀 Deploying AMD GPU-Accelerated Offline TTS (via DirectML)..." -ForegroundColor Green

# --- 1. Ensure Python ---
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python not found. Install Python 3.10 (64-bit) with 'Add to PATH'." -ForegroundColor Red
    exit 1
}

# --- 2. Setup directory ---
if (!(Test-Path $TTSRoot)) { New-Item -ItemType Directory -Path $TTSRoot | Out-Null }
Set-Location $TTSRoot

# --- 3. Create virtual env ---
python -m venv tts-dml
$env:VIRTUAL_ENV = "$TTSRoot\tts-dml"
$env:PATH = "$env:VIRTUAL_ENV\Scripts;$env:PATH"

# --- 4. Install PyTorch-DirectML ---
Write-Host "📦 Installing PyTorch-DirectML..." -ForegroundColor Cyan
pip install --upgrade pip
pip install torch-directml

# Verify DirectML device
python -c "import torch_directml; dml = torch_directml.device(); print('DirectML device:', dml); print('GPU name:', torch_directml.device_name(0))"

# --- 5. Install Coqui TTS (CPU version first) ---
# We'll patch it to use DirectML
pip install TTS

# --- 6. Create patched TTS synthesizer ---
$synthesizePy = @'
import os
import argparse
import torch
import torch_directml
from TTS.api import TTS

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--text", required=True)
    parser.add_argument("--output", default="output.wav")
    parser.add_argument("--speaker_id", type=int, default=10)  # VCTK speaker
    args = parser.parse_args()

    # Use DirectML device
    device = torch_directml.device()
    print(f"Using DirectML device: {torch_directml.device_name(0)}")

    # Load text
    if os.path.isfile(args.text):
        with open(args.text, 'r', encoding='utf-8') as f:
            text = f.read().strip()
    else:
        text = args.text

    # Force model to load without espeak (Windows-compatible)
    os.environ["ESPEAK_LIB_PATH"] = ""  # disable espeak

    # Initialize TTS - will auto-download if not present
    tts = TTS(model_name="tts_models/en/vctk/vits", progress_bar=True, gpu=False)
    
    # Move model to DirectML device
    tts.synthesizer.tts_model.to(device)
    tts.synthesizer.tts_model.eval()

    # Override internal device
    tts.synthesizer.tts_model.device = device

    # Synthesize
    print("Synthesizing...")
    wav = tts.synthesizer.tts_model.inference(text, speaker_id=args.speaker_id)
    
    # Save
    from TTS.utils.audio import AudioProcessor
    ap = AudioProcessor(**tts.synthesizer.output_sample_rate)
    ap.save_wav(wav, args.output)
    print(f"✅ Saved to {os.path.abspath(args.output)}")

if __name__ == "__main__":
    main()
'@

Set-Content -Path "synthesize_dml.py" -Value $synthesizePy

# --- 7. Create runner script ---
$runScript = @'
cd /d "%~dp0"
call tts-dml\Scripts\activate.bat
python synthesize_dml.py %*

Set-Content -Path "narrate.bat" -Value $runScript

Write-Host "✅ Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📌 Usage:"
Write-Host "   narrate.bat --text ""Welcome to training.""" --output welcome.wav"
Write-Host "   narrate.bat --text script.txt --output lesson.wav"
Write-Host ""
Write-Host "💡 First run will download the model (~1.2 GB) — ensure internet for setup only"
'@