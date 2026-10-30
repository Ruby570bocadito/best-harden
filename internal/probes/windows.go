//go:build windows

package probes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func init() {
	Register(registryProbe{})
	Register(secpolProbe{})
	Register(auditpolProbe{})
	Register(serviceProbe{})
	Register(psProbe{})
}

// sys32 devuelve la ruta absoluta de una herramienta del sistema. Nunca se
// confía en el PATH para evitar secuestro de binarios.
func sys32(exe string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", exe)
}

// privateTempDir crea un directorio temporal sin espacios en la ruta (algunas
// herramientas como auditpol no aceptan rutas entrecomilladas).
func privateTempDir() (string, error) {
	base := filepath.Join(os.Getenv("SystemRoot"), "Temp")
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "bastion-")
	if err != nil {
		dir, err = os.MkdirTemp("", "bastion-")
	}
	return dir, err
}

// --- registry ----------------------------------------------------------

type registryProbe struct{}

func (registryProbe) Name() string         { return "registry" }
func (registryProbe) DefaultField() string { return "value" }

func (registryProbe) Collect(_ context.Context, p Params) (Observation, error) {
	if err := p.Require("path", "name"); err != nil {
		return Observation{}, err
	}
	rootName, sub, err := splitRegistryPath(p.String("path"))
	if err != nil {
		return Observation{}, err
	}
	root := map[string]registry.Key{"HKLM": registry.LOCAL_MACHINE, "HKU": registry.USERS, "HKCR": registry.CLASSES_ROOT}[rootName]
	name := p.String("name")
	src := p.String("path") + `\` + name

	if !strings.Contains(sub, "*") {
		v, typ, found, err := readRegValue(root, sub, name)
		if err != nil {
			return Observation{}, permissionErr(err, src)
		}
		if !found {
			return Observation{Found: false, Source: src}, nil
		}
		return Observation{Found: true, Source: src, Fields: map[string]any{"value": v, "type": typ}}, nil
	}

	// Comodín en un segmento (p. ej. ...\Interfaces\Tcpip_*): devuelve la
	// lista de valores de todas las subclaves que coinciden.
	segs := strings.Split(sub, `\`)
	idx := -1
	for i, s := range segs {
		if strings.Contains(s, "*") {
			idx = i
			break
		}
	}
	prefix := strings.Join(segs[:idx], `\`)
	suffix := strings.Join(segs[idx+1:], `\`)
	k, err := registry.OpenKey(root, prefix, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return Observation{Found: false, Source: src}, nil
	}
	if err != nil {
		return Observation{}, permissionErr(err, p.String("path"))
	}
	names, err := k.ReadSubKeyNames(-1)
	k.Close()
	if err != nil {
		return Observation{}, err
	}
	var values []any
	for _, n := range names {
		if ok, _ := path.Match(strings.ToLower(segs[idx]), strings.ToLower(n)); !ok {
			continue
		}
		full := prefix + `\` + n
		if suffix != "" {
			full += `\` + suffix
		}
		if v, _, found, err := readRegValue(root, full, name); err == nil && found {
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return Observation{Found: false, Source: src}, nil
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{"value": values}}, nil
}

func readRegValue(root registry.Key, sub, name string) (any, string, bool, error) {
	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	defer k.Close()
	_, typ, err := k.GetValue(name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	switch typ {
	case registry.DWORD, registry.QWORD:
		v, _, err := k.GetIntegerValue(name)
		return v, map[uint32]string{registry.DWORD: "DWORD", registry.QWORD: "QWORD"}[typ], true, err
	case registry.SZ, registry.EXPAND_SZ:
		v, _, err := k.GetStringValue(name)
		return v, "SZ", true, err
	case registry.MULTI_SZ:
		v, _, err := k.GetStringsValue(name)
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out, "MULTI_SZ", true, err
	default:
		v, _, err := k.GetBinaryValue(name)
		return hex.EncodeToString(v), "BINARY", true, err
	}
}

// --- secpol: directiva de seguridad local (secedit /export) ---------------

type secpolProbe struct{}

func (secpolProbe) Name() string         { return "secpol" }
func (secpolProbe) DefaultField() string { return "value" }

func (secpolProbe) Collect(ctx context.Context, p Params) (Observation, error) {
	if err := p.Require("section", "key"); err != nil {
		return Observation{}, err
	}
	data, err := cached(ctx, "secpol", func() (map[string]map[string]string, error) { return exportSecpol(ctx) })
	if err != nil {
		return Observation{}, err
	}
	section := strings.ToLower(p.String("section"))
	key := strings.ToLower(p.String("key"))
	src := fmt.Sprintf("secedit [%s] %s", p.String("section"), p.String("key"))
	raw, ok := data[section][key]
	if !ok {
		return Observation{Found: false, Source: src}, nil
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{"value": secpolValue(section, raw)}}, nil
}

// ReadAuditpol lee la directiva de auditoría avanzada actual (sin caché).
func ReadAuditpol(ctx context.Context) (map[string]AuditSetting, error) {
	// auditpol /backup exige un token elevado: sin él ni se intenta.
	if !Privileged() {
		return nil, NeedsPrivilege("la directiva de auditoría solo se puede leer como administrador")
	}
	dir, err := privateTempDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "audit.csv")
	res, err := runCmd(ctx, sys32("auditpol.exe"), "/backup", "/file:"+out)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(out)
	if res.ExitCode != 0 || err != nil {
		return nil, fmt.Errorf("auditpol /backup falló (código %d)", res.ExitCode)
	}
	return parseAuditpolBackup(decodeText(b))
}

// ReadSecpol lee la directiva de seguridad local actual (sin caché).
func ReadSecpol(ctx context.Context) (map[string]map[string]string, error) { return exportSecpol(ctx) }

// QueryPS ejecuta una consulta PowerShell de la lista blanca (sin caché).
func QueryPS(ctx context.Context, name string) (map[string]any, error) {
	return QueryPSEnv(ctx, name)
}

// QueryPSEnv ejecuta una consulta de la lista blanca pasándole datos por
// variables de entorno (NOMBRE=valor): el script los lee de $env y nunca
// forman parte de su texto.
func QueryPSEnv(ctx context.Context, name string, env ...string) (map[string]any, error) {
	q, ok := psQueries[name]
	if !ok {
		return nil, fmt.Errorf("consulta PowerShell %q no permitida", name)
	}
	if psAdminQueries[name] && !Privileged() {
		return nil, NeedsPrivilege("%s solo responde como administrador", q.desc)
	}
	data, err := runPS(ctx, q.script, env...)
	if err != nil {
		return nil, err
	}
	if code, ok := data["__na"].(string); ok {
		return nil, NotApplicable("%s", psNotApplicable[code])
	}
	if msg, ok := data["__err"].(string); ok {
		msg = strings.Join(strings.Fields(msg), " ")
		if !Privileged() {
			return nil, NeedsPrivilege("%s: %s", q.desc, msg)
		}
		return nil, fmt.Errorf("%s: %s", q.desc, msg)
	}
	return data, nil
}

// PrivateTempDir crea un directorio temporal privado sin espacios en la ruta.
func PrivateTempDir() (string, error) { return privateTempDir() }

// System32 devuelve la ruta absoluta de una herramienta del sistema.
func System32(exe string) string { return sys32(exe) }

func exportSecpol(ctx context.Context) (map[string]map[string]string, error) {
	if !Privileged() {
		return nil, NeedsPrivilege("la directiva de seguridad local solo se puede leer como administrador")
	}
	dir, err := privateTempDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "secpol.inf")
	res, err := runCmd(ctx, sys32("secedit.exe"), "/export", "/cfg", out, "/areas", "SECURITYPOLICY", "USER_RIGHTS", "/quiet")
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(out)
	if res.ExitCode != 0 || err != nil {
		return nil, fmt.Errorf("secedit /export falló (código %d)", res.ExitCode)
	}
	return parseSecpolINF(decodeText(b)), nil
}

// --- auditpol: directiva de auditoría avanzada -------------------------------

type auditpolProbe struct{}

func (auditpolProbe) Name() string         { return "auditpol" }
func (auditpolProbe) DefaultField() string { return "value" }

func (auditpolProbe) Collect(ctx context.Context, p Params) (Observation, error) {
	if err := p.Require("guid"); err != nil {
		return Observation{}, err
	}
	data, err := cached(ctx, "auditpol", func() (map[string]AuditSetting, error) { return ReadAuditpol(ctx) })
	if err != nil {
		return Observation{}, err
	}
	guid := normGUID(p.String("guid"))
	s, ok := data[guid]
	src := "auditpol {" + guid + "}"
	if !ok {
		return Observation{Found: false, Source: src}, nil
	}
	if s.Name != "" {
		src = "auditpol " + s.Name
	}
	return Observation{Found: true, Source: src, Fields: map[string]any{"value": s.Value, "name": s.Name}}, nil
}

// --- service: configuración y estado de servicios ----------------------------

type serviceProbe struct{}

func (serviceProbe) Name() string         { return "service" }
func (serviceProbe) DefaultField() string { return "start_type" }

func (serviceProbe) Collect(_ context.Context, p Params) (Observation, error) {
	if err := p.Require("name"); err != nil {
		return Observation{}, err
	}
	name := p.String("name")
	src := "servicio " + name
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Observation{}, fmt.Errorf("no se pudo abrir el administrador de servicios: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Observation{}, err
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return Observation{Found: false, Source: src}, nil
	}
	if err != nil {
		return Observation{}, err
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return Observation{}, err
	}
	st, err := s.Query()
	if err != nil {
		return Observation{}, err
	}
	start := map[uint32]string{0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}[cfg.StartType]
	if cfg.StartType == mgr.StartAutomatic && cfg.DelayedAutoStart {
		start = "auto-delayed"
	}
	state := map[svc.State]string{
		svc.Stopped: "stopped", svc.StartPending: "start-pending", svc.StopPending: "stop-pending",
		svc.Running: "running", svc.ContinuePending: "continue-pending", svc.PausePending: "pause-pending", svc.Paused: "paused",
	}[st.State]
	return Observation{Found: true, Source: src, Fields: map[string]any{
		"start_type":   start,
		"state":        state,
		"display_name": cfg.DisplayName,
	}}, nil
}

// --- ps: consultas PowerShell FIJAS (lista blanca) ---------------------------

// psQueries son las únicas consultas PowerShell que puede pedir una regla.
// Las reglas eligen una por nombre; no pueden aportar código. Los scripts no
// usan comillas dobles para que el paso de argumentos sea seguro.
// psAdminQueries son las consultas que Windows solo responde con un token
// elevado: sin él no se ejecutan (y no se confunden con "no disponible").
var psAdminQueries = map[string]bool{"bitlocker_os": true, "optional_features": true, "smb_shares": true, "defender_exclusions": true}

var psQueries = map[string]struct{ desc, script string }{
	"smb_server": {"Get-SmbServerConfiguration",
		`Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,EncryptData,RejectUnencryptedAccess | ConvertTo-Json -Compress`},
	"smb_client": {"Get-SmbClientConfiguration",
		`Get-SmbClientConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature,EnableInsecureGuestLogons | ConvertTo-Json -Compress`},
	"firewall": {"Get-NetFirewallProfile (ActiveStore)",
		`$o=@{}; Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { $o[[string]$_.Name]=@{Enabled=[string]$_.Enabled;DefaultInboundAction=[string]$_.DefaultInboundAction;DefaultOutboundAction=[string]$_.DefaultOutboundAction;LogBlocked=[string]$_.LogBlocked} }; $o | ConvertTo-Json -Compress`},
	"defender_status": {"Get-MpComputerStatus",
		`try { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected,AntivirusSignatureAge | ConvertTo-Json -Compress } catch { @{__na='defender'} | ConvertTo-Json -Compress }`},
	// Exclusiones de Defender que anulan la protección: unidades enteras,
	// carpetas temporales o de descargas, extensiones ejecutables y
	// procesos que el malware usa para ejecutarse. Sin privilegios Windows
	// las oculta («N/A: Must be an administrator…»): solo como administrador.
	"defender_exclusions": {"Get-MpPreference (exclusiones)",
		`try { $p = Get-MpPreference; $all = @(@($p.ExclusionPath) + @($p.ExclusionExtension) + @($p.ExclusionProcess) | Where-Object { $_ }); ` +
			// Con HideExclusionsFromLocalAdmins ni un administrador las ve.
			`if ($all | Where-Object { [string]$_ -like 'N/A*' }) { @{__na='defender_hidden'} | ConvertTo-Json -Compress; return }; ` +
			`$risky = New-Object System.Collections.ArrayList; ` +
			`foreach ($x in @($p.ExclusionPath)) { if ($x -and ($x -match '^[A-Za-z]:\\?$' -or $x -match '^\*|^[A-Za-z]:\\\*' -or $x -match '\\(temp|tmp|downloads|descargas|users\\public|appdata\\local\\temp)(\\|$)' -or $x -match '\\appdata(\\(roaming|local|locallow))?\\?$' -or $x -match '^%(temp|tmp|userprofile|appdata|localappdata)%\\?$' -or $x -match '^[A-Za-z]:\\(users|windows|programdata)\\?$')) { [void]$risky.Add('ruta ' + $x) } }; ` +
			`foreach ($x in @($p.ExclusionExtension)) { if ($x -and $x.TrimStart('.') -match '^(\*|exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi|lnk)$') { [void]$risky.Add('extensión ' + $x) } }; ` +
			`foreach ($x in @($p.ExclusionProcess)) { if ($x -and [IO.Path]::GetFileName($x) -match '^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec|certutil|bitsadmin)\.exe$') { [void]$risky.Add('proceso ' + $x) } }; ` +
			`@{Total=$all.Count; Risky=[string]::Join('; ', $risky)} | ConvertTo-Json -Compress } catch { @{__na='defender'} | ConvertTo-Json -Compress }`},
	"defender_prefs": {"Get-MpPreference",
		`try { Get-MpPreference | Select-Object MAPSReporting,PUAProtection,EnableNetworkProtection,DisableRealtimeMonitoring,SubmitSamplesConsent,DisableScriptScanning | ConvertTo-Json -Compress } catch { @{__na='defender'} | ConvertTo-Json -Compress }`},
	"defender_asr": {"Get-MpPreference (reglas ASR)",
		`try { $p=Get-MpPreference; $o=@{}; $ids=@($p.AttackSurfaceReductionRules_Ids); $acts=@($p.AttackSurfaceReductionRules_Actions); for($i=0;$i -lt $ids.Count;$i++){ if($ids[$i]){ $o[([string]$ids[$i]).ToLower()]=[int]$acts[$i] } }; $o | ConvertTo-Json -Compress } catch { @{__na='defender'} | ConvertTo-Json -Compress }`},
	"bitlocker_os": {"Get-BitLockerVolume (unidad del sistema)",
		`try { $v=Get-BitLockerVolume -MountPoint $env:SystemDrive; @{ProtectionStatus=[string]$v.ProtectionStatus;VolumeStatus=[string]$v.VolumeStatus;EncryptionMethod=[string]$v.EncryptionMethod;KeyProtectors=@($v.KeyProtector | ForEach-Object {[string]$_.KeyProtectorType})} | ConvertTo-Json -Compress } catch { @{__na='bitlocker'} | ConvertTo-Json -Compress }`},
	"device_guard": {"Win32_DeviceGuard",
		`try { $d=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard; @{VirtualizationBasedSecurityStatus=[int]$d.VirtualizationBasedSecurityStatus;SecurityServicesConfigured=@($d.SecurityServicesConfigured | ForEach-Object {[int]$_});SecurityServicesRunning=@($d.SecurityServicesRunning | ForEach-Object {[int]$_})} | ConvertTo-Json -Compress } catch { @{__na='deviceguard'} | ConvertTo-Json -Compress }`},
	// Para "bastion surface": recursos compartidos (sin los administrativos)
	// con el SID de cada cuenta, para no depender del idioma de los nombres.
	"smb_shares": {"Get-SmbShare / Get-SmbShareAccess",
		`try { $o=@(); Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { $n=[string]$_.Name; $acc=@(Get-SmbShareAccess -Name $n -ErrorAction SilentlyContinue | ForEach-Object { $sid=''; try { $sid=(New-Object System.Security.Principal.NTAccount($_.AccountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}; @{Account=[string]$_.AccountName;SID=$sid;Right=[string]$_.AccessRight;Type=[string]$_.AccessControlType} }); $o+=@{Name=$n;Path=[string]$_.Path;Access=$acc} }; @{shares=$o} | ConvertTo-Json -Compress -Depth 5 } catch { @{__err=$_.Exception.Message} | ConvertTo-Json -Compress }`},
	// Política efectiva del Firewall de Windows (COM HNetCfg.FwPolicy2, que
	// es mucho más rápido que Get-NetFirewallRule): perfiles activos, estado
	// y acción de entrada por defecto, y reglas de entrada habilitadas.
	"firewall_policy": {"HNetCfg.FwPolicy2 (Firewall de Windows)",
		`try { $p=New-Object -ComObject HNetCfg.FwPolicy2; $cur=[int]$p.CurrentProfileTypes; $prof=@(); foreach($b in 1,2,4){ $prof+=@{Bit=$b;Enabled=[bool]$p.FirewallEnabled($b);BlockInbound=([int]$p.DefaultInboundAction($b) -eq 0);Active=(($cur -band $b) -ne 0)} }; $rules=New-Object System.Collections.ArrayList; foreach($r in $p.Rules){ if($r.Enabled -and $r.Direction -eq 1){ $ifs=''; try { if($r.Interfaces){ $ifs=[string]::Join(',', @($r.Interfaces)) } } catch {}; $pk=''; $uo=''; try { $pk=[string]$r.LocalAppPackageId; $uo=[string]$r.LocalUserOwner } catch {}; [void]$rules.Add(@{N=[string]$r.Name;A=[int]$r.Action;P=[int]$r.Protocol;L=[string]$r.LocalPorts;RP=[string]$r.RemotePorts;App=[string]$r.ApplicationName;S=[string]$r.ServiceName;Pr=[int]$r.Profiles;LA=[string]$r.LocalAddresses;R=[string]$r.RemoteAddresses;I=$ifs;IT=[string]$r.InterfaceTypes;Pk=$pk;U=$uo}) } }; @{profiles=$prof;rules=$rules} | ConvertTo-Json -Compress -Depth 4 } catch { @{__err=$_.Exception.Message} | ConvertTo-Json -Compress }`},
	// Solo los perfiles: las reglas se leen del registro (bastion surface).
	"firewall_profiles": {"HNetCfg.FwPolicy2 (perfiles del Firewall de Windows)",
		`try { $p=New-Object -ComObject HNetCfg.FwPolicy2; $cur=[int]$p.CurrentProfileTypes; $prof=@(); foreach($b in 1,2,4){ $prof+=@{Bit=$b;Enabled=[bool]$p.FirewallEnabled($b);BlockInbound=([int]$p.DefaultInboundAction($b) -eq 0);Active=(($cur -band $b) -ne 0)} }; @{profiles=$prof} | ConvertTo-Json -Compress -Depth 4 } catch { @{__err=$_.Exception.Message} | ConvertTo-Json -Compress }`},
	// Miembros del grupo Administradores por SID (S-1-5-32-544). Si
	// Get-LocalGroupMember falla (SIDs huérfanos), se usa ADSI.
	"local_admins": {"miembros de Administradores (S-1-5-32-544)",
		`$m=@(); try { Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction Stop | ForEach-Object { $m+=@{Name=[string]$_.Name;Type=[string]$_.ObjectClass;Source=[string]$_.PrincipalSource} } } catch { try { $g=(New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]; ([ADSI]"WinNT://$env:COMPUTERNAME/$g,group").psbase.Invoke('Members') | ForEach-Object { $m+=[string]$_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null) } } catch { $m=@{__err=$_.Exception.Message} } }; if ($m -is [hashtable]) { $m | ConvertTo-Json -Compress } else { @{members=$m} | ConvertTo-Json -Compress -Depth 4 }`},
	// Firma Authenticode de los ficheros de BASTION_PATHS (una ruta por
	// línea): la incrustada o la de un catálogo, como la de casi todo
	// Windows.
	"file_signatures": {"Get-AuthenticodeSignature",
		`$o=@{}; foreach ($p in ($env:BASTION_PATHS -split [char]10)) { if (-not $p) { continue }; try { $s=Get-AuthenticodeSignature -LiteralPath $p; $o[$p]=@{status=[string]$s.Status; signer=[string]$s.SignerCertificate.Subject} } catch { $o[$p]=@{status='Error'; signer=''} } }; @{files=$o} | ConvertTo-Json -Compress -Depth 4`},
	"optional_features": {"Get-WindowsOptionalFeature",
		`$want=@('SMB1Protocol','MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2','TelnetClient','TFTP'); $o=@{}; try { Get-WindowsOptionalFeature -Online | Where-Object { $want -contains $_.FeatureName } | ForEach-Object { $o[[string]$_.FeatureName]=[string]$_.State } } catch { $o=@{__err=$_.Exception.Message} }; $o | ConvertTo-Json -Compress`},
}

var psNotApplicable = map[string]string{
	"defender":        "Microsoft Defender no está disponible o no está activo (¿antivirus de terceros?)",
	"defender_hidden": "una directiva oculta las exclusiones de Defender incluso a los administradores (HideExclusionsFromLocalAdmins)",
	"bitlocker":       "BitLocker no está disponible en esta edición de Windows",
	"deviceguard":     "la información de Device Guard/VBS no está disponible",
}

type psProbe struct{}

func (psProbe) Name() string         { return "ps" }
func (psProbe) DefaultField() string { return "value" }

func (psProbe) Collect(ctx context.Context, p Params) (Observation, error) {
	if err := p.Require("query"); err != nil {
		return Observation{}, err
	}
	name := p.String("query")
	q, ok := psQueries[name]
	if !ok {
		return Observation{}, fmt.Errorf("consulta PowerShell %q no permitida", name)
	}
	if psAdminQueries[name] && !Privileged() {
		return Observation{}, NeedsPrivilege("%s solo responde como administrador", q.desc)
	}
	data, err := cached(ctx, "ps:"+name, func() (map[string]any, error) { return runPS(ctx, q.script) })
	if err != nil {
		return Observation{}, err
	}
	if code, ok := data["__na"].(string); ok {
		return Observation{}, NotApplicable("%s", psNotApplicable[code])
	}
	if msg, ok := data["__err"].(string); ok {
		msg = strings.Join(strings.Fields(msg), " ")
		if !Privileged() {
			return Observation{}, NeedsPrivilege("%s: %s", q.desc, msg)
		}
		return Observation{}, fmt.Errorf("%s: %s", q.desc, msg)
	}
	return Observation{Found: true, Source: "PowerShell " + q.desc, Fields: data}, nil
}

func runPS(ctx context.Context, script string, env ...string) (map[string]any, error) {
	prefix := `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;`
	res, err := runCmdEnv(ctx, env, sys32(`WindowsPowerShell\v1.0\powershell.exe`),
		"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefix+script)
	if err != nil {
		return nil, err
	}
	out := strings.TrimSpace(res.Stdout)
	if out == "" {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = fmt.Sprintf("sin salida (código %d)", res.ExitCode)
		}
		return nil, fmt.Errorf("PowerShell: %s", truncate(msg, 300))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		return nil, fmt.Errorf("PowerShell devolvió JSON inválido: %w", err)
	}
	return m, nil
}
