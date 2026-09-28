; PhantomFix — Inno Setup Script
; Versão: 1.0.0
;
; Pré-requisitos:
;   1. PyInstaller já gerou dist/PhantomFix.exe
;   2. Inno Setup 6+ instalado na máquina de build
;
; Para compilar:
;   Abrir este arquivo no Inno Setup Compiler → Build → Compile
;   O instalador será gerado em: installer/PhantomFix-Setup.exe

#define AppName      "PhantomFix"
#define AppVersion   "1.0.0"
#define AppPublisher "PhantomFix Team"
#define AppURL       "https://phantomfix.com.br"
#define AppExeName   "PhantomFix.exe"

[Setup]
AppId={{8F3A2B1C-4D5E-6F7A-8B9C-0D1E2F3A4B5C}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=installer
OutputBaseFilename=PhantomFix-Setup
SetupIconFile=phantom.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
; Não requer admin — instala por usuário
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "startupentry"; Description: "Iniciar PhantomFix automaticamente com o Windows"; GroupDescription: "Opções adicionais:"; Flags: checked

[Files]
Source: "dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";          Filename: "{app}\{#AppExeName}"
Name: "{group}\Desinstalar {#AppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}";  Filename: "{app}\{#AppExeName}"; Tasks: ; Flags: unchecked

[Registry]
; Iniciar com o Windows (apenas para o usuário atual)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
  ValueType: string; ValueName: "{#AppName}"; \
  ValueData: """{app}\{#AppExeName}"""; \
  Flags: uninsdeletevalue; Tasks: startupentry

[Run]
; Inicia o app ao final da instalação
Filename: "{app}\{#AppExeName}"; \
  Description: "Iniciar {#AppName} agora"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
; Encerra o processo antes de desinstalar
Filename: "taskkill.exe"; Parameters: "/f /im {#AppExeName}"; Flags: runhidden

[Code]
// Verifica se o app já está rodando antes de instalar
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/f /im {#AppExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := True;
end;
