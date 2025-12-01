# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21005.1");
  script_cve_id("CVE-2025-10230", "CVE-2025-9640");
  script_tag(name:"creation_date", value:"2025-11-28 04:13:19 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-07 20:15:35 +0000 (Fri, 07 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21005-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521005-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251280");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023386.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2025:21005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

Update to 4.22.5:

 * CVE-2025-10230: Command injection via WINS server hook script (bsc#1251280).
 * CVE-2025-9640: uninitialized memory disclosure via vfs_streams_xattr (bsc#1251279).

- Relax samba-gpupdate requirement for cepces, certmonger, and sscep
 to a recommends. They are only required if utilizing certificate
 auto enrollment (bsc#1249087).

- Disable timeouts for smb.service so that possibly slow running
 ExecStartPre script 'update-samba-security-profile' doesn't
 cause service start to fail due to timeouts (bsc#1249181).

- Ensure semanage is pulled in as a requirement when samba in
 installed when selinux security access mechanism that is used
 (bsc#1249180).

- don't attempt to label paths that don't exist, also remove
 unecessary evaluation of semange & restorecon cmds (bsc#1249179).

Update to 4.22.4:

 * netr_LogonSamLogonEx returns NR_STATUS_ACCESS_DENIED with
 SysvolReady=0
 * getpwuid does not shift to new DC when current DC is down
 * Windows security hardening locks out schannel'ed netlogon dc
 calls like netr_DsRGetDCName-
 * Unresponsive second DC can cause idmapping failure when using
 idmap_ad-
 * kinit command is failing with Missing cache Error.
 * Figuring out the DC name from IP address fails and breaks
 fork_domain_child().
 * vfs_streams_depot fstatat broken.
 * Delayed leader broadcast can block ctdb forever.
 * Apparently there is a conflict between shadow_copy2 module
 and virusfilter (action quarantine).
 * Fix handling of empty GPO link.
 * SMB ACL inheritance doesn't work for files created.

- adjust gpgme build dependency for future-proofing");

  script_tag(name:"affected", value:"'samba' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-pcp-pmda", rpm:"ctdb-pcp-pmda~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ldb-tools", rpm:"ldb-tools~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb-devel", rpm:"libldb-devel~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb2", rpm:"libldb2~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ldb", rpm:"python3-ldb~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc", rpm:"samba-ad-dc~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs", rpm:"samba-ad-dc-libs~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dcerpc", rpm:"samba-dcerpc~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules", rpm:"samba-dsdb-modules~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gpupdate", rpm:"samba-gpupdate~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap", rpm:"samba-ldb-ldap~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-tool", rpm:"samba-tool~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs", rpm:"samba-winbind-libs~4.22.5+git.431.dc5a539f124~160000.1.1", rls:"SLES16.0.0"))) {
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
