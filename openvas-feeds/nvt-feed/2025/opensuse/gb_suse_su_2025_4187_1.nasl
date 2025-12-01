# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4187.1");
  script_cve_id("CVE-2024-0132", "CVE-2024-0133", "CVE-2024-0134", "CVE-2024-0135", "CVE-2024-0136", "CVE-2024-0137", "CVE-2025-23266", "CVE-2025-23267", "CVE-2025-23359");
  script_tag(name:"creation_date", value:"2025-11-26 04:10:41 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-06 14:07:29 +0000 (Mon, 06 Oct 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4187-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4187-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254187-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246860");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023342.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-container-toolkit' package(s) announced via the SUSE-SU-2025:4187-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nvidia-container-toolkit fixes the following issues:

- Update to version 1.18.0:
 - This is a major release and includes the following high-level changes:
 - The default mode of the NVIDIA Container Runtime has been updated to make use
 of a just-in-time-generated CDI specification instead of defaulting to the legacy mode.
 - Added a systemd unit to generate CDI specifications for available devices automatically. This allows
 native CDI support in container engines such as Docker and Podman to be used without additional steps.

- Security issues fixed:
 - CVE-2024-0133: Fixed data tampering in host file system via specially
 crafted container image (bsc#1231032)
 - CVE-2024-0132: Fixed time-of-check time-of-use (TOCTOU) race condition
 in default configuration via specifically crafted container image
 (bsc#1231033)
 - CVE-2024-0134: Fixed specially-crafted container image can lead to
 the creation of unauthorized files on the host (bsc#1232855)
 - CVE-2024-0135: Fixed Improper Isolation or Compartmentalization in
 NVIDIA Container Toolkit (bsc#1236496)
 - CVE-2024-0136: Fixed Improper Isolation or Compartmentalization in
 NVIDIA Container Toolkit (bsc#1236497)
 - CVE-2024-0137: Fixed Improper Isolation or Compartmentalization in
 NVIDIA Container Toolkit (bsc#1236498)
 - CVE-2025-23359: Fixed TOCTOU Vulnerability in NVIDIA Container Toolkit
 (bsc#1237085)
 - CVE-2025-23267: Fixed link following can lead to container escape
 (bsc#1246614)
 - CVE-2025-23266: Fixed hook initialization might lead to escalation
 of privileges (bsc#1246860)");

  script_tag(name:"affected", value:"'nvidia-container-toolkit' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"nvidia-container-toolkit", rpm:"nvidia-container-toolkit~1.18.0~150200.5.17.1", rls:"openSUSELeap15.6"))) {
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
