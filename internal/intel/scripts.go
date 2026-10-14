package intel

// The probe scripts.
//
// Rules every one of them follows:
//
//   - Read only. Nothing here installs, writes, starts, stops or configures
//     anything. A console that silently changes the machines it inventories is
//     not an inventory tool, and this is the file where that would creep in.
//   - Never block. Anything that could wait on hardware, a lock or a network
//     goes through the timeout helper. A hung command costs the whole report,
//     because the end marker never arrives.
//   - Never fail loudly. Every field is independent and optional; a missing
//     binary or an unreadable file yields an empty value, not an abort.
//   - One fact per line, "key<TAB>value". Repeating a key makes it a list,
//     which is how disks, interfaces and GPUs are reported. Values are
//     stripped of tabs and newlines at the point of printing, so the format
//     cannot be broken by whatever a command happens to emit.
//
// __BEGIN__ and __END__ are substituted before sending. They bracket the
// output so the parser can find it among whatever else is on the terminal.

const linuxScript = `
p(){ printf '%s\t%s\n' "$1" "$(printf '%s' "$2" | tr '\n\t' '  ')"; }
r(){ if [ -r "$1" ]; then tr -d '\n\t' < "$1" | cut -c1-200; fi; }
t(){ if command -v timeout >/dev/null 2>&1; then timeout 5 "$@"; else "$@"; fi; }
printf '%s\n' '__BEGIN__'
p probe.platform linux

# --- identity ---
p host.name "$(uname -n 2>/dev/null)"
p host.fqdn "$(hostname -f 2>/dev/null)"
p user.current "$(id -un 2>/dev/null)"
p user.logged "$(t who 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')"

# --- operating system ---
if [ -r /etc/os-release ]; then . /etc/os-release 2>/dev/null; fi
p os.name "$PRETTY_NAME"
p os.id "$ID"
p os.version "$VERSION_ID"
p os.kernel "$(uname -r 2>/dev/null)"
p os.arch "$(uname -m 2>/dev/null)"
p os.virt "$(t systemd-detect-virt 2>/dev/null)"
p os.uptime_s "$(cut -d. -f1 /proc/uptime 2>/dev/null)"
p os.boot "$(uptime -s 2>/dev/null)"
p os.load "$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
p os.shell "$(getent passwd "$(id -un 2>/dev/null)" 2>/dev/null | cut -d: -f7)"

# --- time and place ---
p time.zone "$(readlink -f /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')"
p time.local "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
p time.offset "$(date +%z 2>/dev/null)"

# --- processor and memory ---
p cpu.model "$(awk -F: '/model name/{sub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)"
p cpu.threads "$(nproc 2>/dev/null)"
p cpu.cores "$(awk -F: '/^cpu cores/{gsub(/ /,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)"
p cpu.mhz "$(awk -F: '/cpu MHz/{printf "%.0f", $2; exit}' /proc/cpuinfo 2>/dev/null)"
p mem.total_kb "$(awk '/^MemTotal/{print $2}' /proc/meminfo 2>/dev/null)"
p mem.available_kb "$(awk '/^MemAvailable/{print $2}' /proc/meminfo 2>/dev/null)"
p mem.swap_kb "$(awk '/^SwapTotal/{print $2}' /proc/meminfo 2>/dev/null)"

# --- firmware and chassis ---
# These sysfs files are world-readable except product_serial, which is 0400.
# Unprivileged runs simply report no serial, which is why r() tests -r first.
p hw.vendor "$(r /sys/class/dmi/id/sys_vendor)"
p hw.model "$(r /sys/class/dmi/id/product_name)"
p hw.version "$(r /sys/class/dmi/id/product_version)"
p hw.serial "$(r /sys/class/dmi/id/product_serial)"
p hw.board "$(r /sys/class/dmi/id/board_name)"
p hw.bios "$(r /sys/class/dmi/id/bios_vendor) $(r /sys/class/dmi/id/bios_version) $(r /sys/class/dmi/id/bios_date)"
p hw.machine_id "$(r /etc/machine-id)"
p hw.battery "$(r /sys/class/power_supply/BAT0/capacity)"

# --- storage ---
t df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1 && $1 !~ /^(tmpfs|devtmpfs|overlay|squashfs|none|udev)$/ {print $6"|"$1"|"$2"|"$3"|"$4"|"$5}' | while IFS= read -r l; do p disk "$l"; done
t lsblk -dno NAME,SIZE,TYPE,MODEL 2>/dev/null | awk '{m=""; for(i=4;i<=NF;i++) m=m (i>4?" ":"") $i; print $1"|"$2"|"$3"|"m}' | while IFS= read -r l; do p blockdev "$l"; done

# --- network ---
t ip -o -4 addr show scope global 2>/dev/null | awk '{print $2"|"$4}' | while IFS= read -r l; do p net.ipv4 "$l"; done
t ip -o -6 addr show scope global 2>/dev/null | awk '{print $2"|"$4}' | while IFS= read -r l; do p net.ipv6 "$l"; done
for i in /sys/class/net/*; do n="${i##*/}"; if [ "$n" != lo ]; then p net.iface "$n|$(r "$i/address")|$(r "$i/operstate")"; fi; done
p net.gateway "$(ip route 2>/dev/null | awk '/^default/{print $3; exit}')"
p net.dns "$(awk '/^nameserver/{printf "%s,", $2}' /etc/resolv.conf 2>/dev/null | sed 's/,$//')"
p net.listening "$(t ss -ltnH 2>/dev/null | awk '{print $4}' | sort -u | tr '\n' ',' | cut -c1-400 | sed 's/,[^,]*$//')"

# --- graphics ---
t lspci 2>/dev/null | grep -iE 'vga|3d controller|display controller' | sed 's/^[^ ]* [^:]*: //' | while IFS= read -r l; do p gpu "$l"; done

# --- installed software ---
p pkg.dpkg "$(t dpkg-query -f '.\n' -W 2>/dev/null | wc -l | tr -d ' ')"
p pkg.rpm "$(t rpm -qa 2>/dev/null | wc -l | tr -d ' ')"
p pkg.pacman "$(t pacman -Qq 2>/dev/null | wc -l | tr -d ' ')"
p pkg.updates "$(t apt-get -s -q -y upgrade 2>/dev/null | grep -c '^Inst')"
p svc.running "$(t systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l | tr -d ' ')"
p svc.failed "$(t systemctl list-units --state=failed --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ',' | sed 's/,$//' | cut -c1-300)"
for b in docker podman python3 node git java; do if command -v "$b" >/dev/null 2>&1; then p sw "$b|$(t "$b" --version 2>&1 | head -1 | cut -c1-80)"; fi; done
printf '%s\n' '__END__'
`

const macScript = `
p(){ printf '%s\t%s\n' "$1" "$(printf '%s' "$2" | tr '\n\t' '  ')"; }
t(){ if command -v timeout >/dev/null 2>&1; then timeout 5 "$@"; else "$@"; fi; }
printf '%s\n' '__BEGIN__'
p probe.platform macos

# --- identity ---
p host.name "$(scutil --get ComputerName 2>/dev/null || uname -n 2>/dev/null)"
p host.fqdn "$(hostname -f 2>/dev/null)"
p user.current "$(id -un 2>/dev/null)"
p user.logged "$(t who 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')"

# --- operating system ---
p os.name "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
p os.version "$(sw_vers -productVersion 2>/dev/null)"
p os.build "$(sw_vers -buildVersion 2>/dev/null)"
p os.kernel "$(uname -r 2>/dev/null)"
p os.arch "$(uname -m 2>/dev/null)"
BT=$(sysctl -n kern.boottime 2>/dev/null | sed 's/.*sec = \([0-9]*\).*/\1/')
p os.uptime_s "$(( $(date +%s 2>/dev/null) - ${BT:-0} ))"
p os.boot "$(date -r "${BT:-0}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
p os.load "$(sysctl -n vm.loadavg 2>/dev/null | tr -d '{}')"
p os.shell "$(dscl . -read "/Users/$(id -un)" UserShell 2>/dev/null | awk '{print $2}')"

# --- time and place ---
p time.zone "$(readlink /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')"
p time.local "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
p time.offset "$(date +%z 2>/dev/null)"

# --- processor and memory ---
p cpu.model "$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
p cpu.threads "$(sysctl -n hw.logicalcpu 2>/dev/null)"
p cpu.cores "$(sysctl -n hw.physicalcpu 2>/dev/null)"
p mem.total_kb "$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 ))"

# --- firmware and chassis ---
p hw.vendor "Apple"
p hw.model "$(sysctl -n hw.model 2>/dev/null)"
p hw.serial "$(t ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'\"' '/IOPlatformSerialNumber/{print $4}')"
p hw.machine_id "$(t ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'\"' '/IOPlatformUUID/{print $4}')"
p hw.battery "$(t pmset -g batt 2>/dev/null | grep -o '[0-9]*%' | head -1 | tr -d '%')"

# --- storage ---
t df -P -k 2>/dev/null | awk 'NR>1 && $1 ~ /^\/dev/ {print $6"|"$1"|"$2"|"$3"|"$4"|"$5}' | while IFS= read -r l; do p disk "$l"; done

# --- network ---
for i in $(ifconfig -l 2>/dev/null); do if [ "$i" != lo0 ]; then p net.iface "$i|$(ifconfig "$i" 2>/dev/null | awk '/ether/{print $2; exit}')|$(ifconfig "$i" 2>/dev/null | awk '/status:/{print $2; exit}')"; fi; done
ifconfig 2>/dev/null | awk '/^[a-z]/{d=$1} /inet /{gsub(/:/,"",d); print d"|"$2}' | while IFS= read -r l; do p net.ipv4 "$l"; done
p net.gateway "$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')"
p net.dns "$(awk '/^nameserver/{printf "%s,", $2}' /etc/resolv.conf 2>/dev/null | sed 's/,$//')"

# --- graphics ---
t system_profiler SPDisplaysDataType 2>/dev/null | awk -F': ' '/Chipset Model/{print $2}' | while IFS= read -r l; do p gpu "$l"; done

# --- installed software ---
p pkg.apps "$(ls /Applications 2>/dev/null | wc -l | tr -d ' ')"
p pkg.brew "$(t brew list --formula 2>/dev/null | wc -l | tr -d ' ')"
for b in docker python3 node git java; do if command -v "$b" >/dev/null 2>&1; then p sw "$b|$(t "$b" --version 2>&1 | head -1 | cut -c1-80)"; fi; done
printf '%s\n' '__END__'
`

// windowsScript is PowerShell, run via -EncodedCommand.
//
// Output goes through [Console]::Out.WriteLine rather than the pipeline:
// anything returned to the pipeline is formatted for display first, and the
// formatter wraps at the console width, which would fold long values onto
// continuation lines and break the one-fact-per-line format.
//
// It is kept short on purpose. The encoded form has to fit on one command
// line, and UTF-16 plus base64 turns every character here into roughly 2.7.
const windowsScript = `
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'
function W($k,$v){[Console]::Out.WriteLine($k+[char]9+(($v|Out-String).Trim() -replace '[\r\n\t]+',' '))}
[Console]::Out.WriteLine('__BEGIN__')
W 'probe.platform' 'windows'
$os=Get-CimInstance Win32_OperatingSystem
$cs=Get-CimInstance Win32_ComputerSystem
$bi=Get-CimInstance Win32_BIOS
$cp=@(Get-CimInstance Win32_Processor)[0]
W 'host.name' $env:COMPUTERNAME
if($cs.Domain){W 'host.fqdn' ($cs.DNSHostName+'.'+$cs.Domain)}
W 'user.current' $cs.UserName
W 'os.name' $os.Caption
W 'os.version' $os.Version
W 'os.build' $os.BuildNumber
W 'os.arch' $os.OSArchitecture
W 'os.install' $os.InstallDate
W 'os.boot' $os.LastBootUpTime
W 'os.uptime_s' ([int](((Get-Date)-$os.LastBootUpTime).TotalSeconds))
W 'time.zone' (Get-TimeZone).Id
W 'time.local' (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
W 'cpu.model' $cp.Name
W 'cpu.cores' $cp.NumberOfCores
W 'cpu.threads' $cp.NumberOfLogicalProcessors
W 'mem.total_kb' ([int64]($cs.TotalPhysicalMemory/1024))
W 'mem.available_kb' $os.FreePhysicalMemory
W 'hw.vendor' $cs.Manufacturer
W 'hw.model' $cs.Model
W 'hw.serial' $bi.SerialNumber
W 'hw.bios' ($bi.Manufacturer+' '+$bi.SMBIOSBIOSVersion)
W 'hw.domain' $cs.Domain
foreach($d in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3 and Size>0'){W 'disk' ($d.DeviceID+'|'+$d.FileSystem+'|'+[int64]($d.Size/1024)+'|'+[int64](($d.Size-$d.FreeSpace)/1024)+'|'+[int64]($d.FreeSpace/1024)+'|'+[int](100*($d.Size-$d.FreeSpace)/$d.Size)+'%')}
foreach($n in Get-NetAdapter){W 'net.iface' ($n.Name+'|'+$n.MacAddress+'|'+$n.Status)}
foreach($a in Get-NetIPAddress -AddressFamily IPv4){if($a.InterfaceAlias -notmatch 'Loopback'){W 'net.ipv4' ($a.InterfaceAlias+'|'+$a.IPAddress+'/'+$a.PrefixLength)}}
W 'net.gateway' ((Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop -join ',')
W 'net.dns' (((Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses|Select-Object -Unique) -join ',')
foreach($g in Get-CimInstance Win32_VideoController){W 'gpu' $g.Name}
W 'pkg.installed' (@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*').Count)
W 'svc.running' (@(Get-Service|Where-Object Status -eq 'Running').Count)
W 'os.updates' (@(Get-HotFix|Sort-Object InstalledOn -Descending|Select-Object -First 1).HotFixID)
[Console]::Out.WriteLine('__END__')
`
