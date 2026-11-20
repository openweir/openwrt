package release

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	sumLine     = regexp.MustCompile(`^([a-f0-9]{64})  ([A-Za-z0-9._-]+)$`)
)

// RenderNotes renders the bilingual installation notes of a GitHub Release from the staged
// assets directory and the SHA256SUMS beside it.
func RenderNotes(repo, version, assets string) (string, error) {
	if !repoPattern.MatchString(repo) {
		return "", errors.New("invalid GitHub repository")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Clean(assets)), "SHA256SUMS"))
	if err != nil {
		return "", err
	}
	sums := strings.TrimRight(string(raw), "\n")
	names := map[string]bool{}
	for _, n := range AllNames(version) {
		names[n] = true
	}
	entries, err := os.ReadDir(assets)
	if err != nil {
		return "", err
	}
	if len(entries) != len(names) {
		return "", errors.New("expected exactly the per-architecture OpenWeir installer packages")
	}
	for _, e := range entries {
		if !names[e.Name()] {
			return "", errors.New("expected exactly the per-architecture OpenWeir installer packages")
		}
	}
	listed := map[string]bool{}
	lines := strings.Split(sums, "\n")
	for _, line := range lines {
		m := sumLine.FindStringSubmatch(line)
		if m == nil || !names[m[2]] {
			return "", errors.New("release checksum entries do not match the installers")
		}
		listed[m[2]] = true
	}
	if len(lines) != len(names) || len(listed) != len(names) {
		return "", errors.New("release checksum entries do not match the installers")
	}
	url := fmt.Sprintf("https://github.com/%s/releases/download/v%s", repo, version)
	var rows []string
	link := func(format, arch string) string {
		if !slices.Contains(Arches[format], arch) {
			return "—"
		}
		name := PackageName(version, format, arch)
		return fmt.Sprintf("[%s](%s/%s)", name, url, name)
	}
	for _, arch := range AllArches {
		rows = append(rows, fmt.Sprintf("| `%s` | %s | %s |", arch, link("ipk", arch), link("apk", arch)))
	}
	r := strings.NewReplacer(
		"{table}", strings.Join(rows, "\n"),
		"{sums}", sums,
		"{ipk}", PackageName(version, "ipk", "<架构 arch>"),
		"{apk}", PackageName(version, "apk", "<架构 arch>"),
		"{repo}", repo,
		"{version}", version,
	)
	return r.Replace(notesTemplate), nil
}

const notesTemplate = "## 安装包 · Downloads\n\n" +
	"按路由器架构选择安装包：在路由器上运行 `. /etc/openwrt_release; echo $DISTRIB_ARCH` 查看架构，在下表中找到对应的一行。OpenWrt 23.05 / 24.10 用 IPK（opkg），25.12 用 APK（apk）。\n\n" +
	"Pick the package for the router's architecture: run `. /etc/openwrt_release; echo $DISTRIB_ARCH` on the router and find it below. OpenWrt 23.05 / 24.10 use the IPK (opkg), 25.12 uses the APK (apk).\n\n" +
	"| OpenWrt 架构 · Architecture | 23.05 / 24.10 · IPK | 25.12 · APK |\n| --- | --- | --- |\n{table}\n\n" +
	"安装包写明了所属架构，装错架构时 opkg / apk 会拒绝安装。离线安装前，请将对应安装包和下方校验值保存到本地，并准备好固件需要的系统依赖。\n\n" +
	"Each package declares its architecture, so opkg / apk refuse a package for another one. For an offline installation, copy the package and its checksum to the router and make sure the firmware's system dependencies are available.\n\n" +
	"### SHA-256\n\n" +
	"将已下载安装包的对应校验行保存为 `SHA256SUMS`，在该包所在目录运行 `sha256sum -c SHA256SUMS`。\n" +
	"Save the checksum line for your downloaded package as `SHA256SUMS`. Run `sha256sum -c SHA256SUMS` in the package directory.\n\n" +
	"```text\n{sums}\n```\n\n" +
	"### OpenWrt 23.05 / 24.10 · IPK\n\n```sh\nopkg install ./{ipk}\n```\n\n" +
	"### OpenWrt 25.12 · APK\n\n```sh\napk add --no-network --allow-untrusted ./{apk}\n```\n\n" +
	"已安装旧版 Cortex-A53 APK 的用户可按[离线升级步骤](https://github.com/{repo}/blob/v{version}/README.zh-CN.md#从旧版-cortex-a53-apk-手动升级)保留已有网络组件。\n" +
	"If upgrading an older Cortex-A53 APK, follow the [offline upgrade instructions](https://github.com/{repo}/blob/v{version}/README.md#manual-upgrade-from-an-older-cortex-a53-apk) to retain existing network components.\n\n" +
	"安装后进入 LuCI 的「服务 → OpenWeir」。mihomo 内核可单独选版，离线时可导入对应架构的原始发行包。\n" +
	"Open **Services → OpenWeir** in LuCI. You can select the mihomo core separately or import its original archive for the router's architecture offline.\n\n"
