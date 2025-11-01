# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891799");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-5995", "CVE-2019-11091", "CVE-2019-11190", "CVE-2019-11486", "CVE-2019-11599", "CVE-2019-2024", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3882", "CVE-2019-3901", "CVE-2019-6133", "CVE-2019-9503");
  script_tag(name:"creation_date", value:"2019-06-01 09:22:29 +0000 (Sat, 01 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 15:17:00 +0000 (Wed, 29 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-1799)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1799");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1799-2");
  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-1799 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

This updated advisory text adds a note about the need to install new binary packages.

CVE-2018-5995

ADLab of VenusTech discovered that the kernel logged the virtual addresses assigned to per-CPU data, which could make it easier to exploit other vulnerabilities.

CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11091 Multiple researchers have discovered vulnerabilities in the way that Intel processor designs implement speculative forwarding of data filled into temporary microarchitectural structures (buffers). This flaw could allow an attacker controlling an unprivileged process to read sensitive information, including from the kernel and all other processes running on the system, or across guest/host boundaries to read host memory. See [link moved to references] for more details. To fully resolve these vulnerabilities it is also necessary to install updated CPU microcode. An updated intel-microcode package (only available in Debian non-free) was provided via DLA-1789-1. The updated CPU microcode may also be available as part of a system firmware ('BIOS') update.

CVE-2019-2024

A use-after-free bug was discovered in the em28xx video capture driver. Local users might be able to use this for denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2019-3459, CVE-2019-3460 Shlomi Oberman, Yuli Shapiro, and Karamba Security Ltd. research team discovered missing range checks in the Bluetooth L2CAP implementation. If Bluetooth is enabled, a nearby attacker could use these to read sensitive information from the kernel.

CVE-2019-3882

It was found that the vfio implementation did not limit the number of DMA mappings to device memory. A local user granted ownership of a vfio device could use this to cause a denial of service (out-of-memory condition).

CVE-2019-3901

Jann Horn of Google reported a race condition that would allow a local user to read performance events from a task after it executes a setuid program. This could leak sensitive information processed by setuid programs. Debian's kernel configuration does not allow unprivileged users to access performance events by default, which fully mitigates this issue.

CVE-2019-6133

Jann Horn of Google found that Policykit's authentication check could be bypassed by a local user creating a process with the same start time and process ID as an older authenticated process. PolicyKit was already updated to fix this in DLA-1644-1. The kernel has additionally been updated to avoid a delay between assigning start time and process ID, which should make the attack impractical.

CVE-2019-9503

Hugues Anguelkov and others at Quarkslab discovered that the brcmfmac (Broadcom wifi FullMAC) driver did not correctly distinguish messages sent by the wifi ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);