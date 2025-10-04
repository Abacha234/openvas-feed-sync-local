# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03448.1");
  script_cve_id("CVE-2025-58058");
  script_tag(name:"creation_date", value:"2025-10-03 04:06:43 +0000 (Fri, 03 Oct 2025)");
  script_version("2025-10-03T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-10-03 15:40:40 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03448-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03448-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503448-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248906");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/041996.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'warewulf4' package(s) announced via the SUSE-SU-2025:03448-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for warewulf4 fixes the following issues:

Update to version 4.6.4.

Security issues fixed:

- CVE-2025-58058: xz: excessive memory consuption when unpacking a large number of corrupted LZMA archives
 (bsc#1248906).

Other issues fixed:

- Convert disk booleans from `wwbool` to `*bool` which allows bools in disk to be set to false via command
 line (bsc#1248768).
- Fix `wwctl` upgrade nodes to handle kernel argument lists (bsc#1227686, bsc#1227465).
- Mark `slurm` as recommeneded in the `warewulf4-overlay-slurm` package (bsc#1246082).
- Switch to `dnsmasq` as default DHCP and TFTP provider.

- v4.6.4 release updates:
 * Update NetworkManager Overlay
 * Disable IPv4 in NetworkManager if no address or route is specified
 * Fix(`wwctl`): create overlay edit `tempfile` in `tmpdir`
 * Add default for systemd name for warewulf in `warewulf.conf`
 * Atomic overlay file application in `wwclient`
 * Simpler names for overlay methods
 * Fix `warewulfd` API behavior when deleting distribution overlay

- v4.6.3 release updates:
 * IPv6 iPXE support
 * Fix a race condition in `wwctl` overlay edit
 * Fixed handling of comma-separated mount options in `fstab` and `ignition` overlays
 * Move `reexec.Init()` to beginning of `wwctl`
 * Added `warewuld` configure option
 * Address copilot review from #1945
 * Bugfix: cloning a site overlay when parent dir does not exist
 * Clone to a site overlay when adding files in `wwapi`
 * Consolidated `createOverlayFile` and `updateOverlayFile` to `addOverlayFile`
 * Support for creating and updating overlay file in `wwapi`
 * Only return overlay files that refer to a path within the overlay
 * Add overlay file deletion support
 * `DELETE /api/overlays/{id}?force=true` can delete overlays in use
 * Restore idempotency of `PUT /api/nodes/{id}`
 * Simplify overlay mtime API and add tests
 * Add node overlay buildtime
 * Improved `netplan` support
 * Rebuild overlays for discovered nodes

- v4.6.2 release updates:
 * (preview) support for provisioning to local disk

- incoperated from v4.6.1:
 * REST API, which is disabled in the default configuration");

  script_tag(name:"affected", value:"'warewulf4' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"warewulf4", rpm:"warewulf4~4.6.4~150500.6.37.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-dracut", rpm:"warewulf4-dracut~4.6.4~150500.6.37.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-man", rpm:"warewulf4-man~4.6.4~150500.6.37.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-overlay", rpm:"warewulf4-overlay~4.6.4~150500.6.37.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-overlay-slurm", rpm:"warewulf4-overlay-slurm~4.6.4~150500.6.37.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"warewulf4-reference-doc", rpm:"warewulf4-reference-doc~4.6.4~150500.6.37.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
