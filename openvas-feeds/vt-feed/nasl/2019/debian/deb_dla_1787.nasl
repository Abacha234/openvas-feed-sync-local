# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891787");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");
  script_tag(name:"creation_date", value:"2019-05-16 02:00:21 +0000 (Thu, 16 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-1787)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1787");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1787");
  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.9' package(s) announced via the DLA-1787 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple researchers have discovered vulnerabilities in the way the Intel processor designs have implemented speculative forwarding of data filled into temporary microarchitectural structures (buffers). This flaw could allow an attacker controlling an unprivileged process to read sensitive information, including from the kernel and all other processes running on the system or cross guest/host boundaries to read host memory.

See [link moved to references] for more details.

To fully resolve these vulnerabilities it is also necessary to install updated CPU microcode. An updated intel-microcode package (only available in Debian non-free) will be provided via a separate DLA. The updated CPU microcode may also be available as part of a system firmware ('BIOS') update.

In addition, this update includes a fix for a regression causing deadlocks inside the loopback driver, which was introduced by the update to 4.9.168 in the last security update.

For Debian 8 Jessie, these problems have been fixed in version 4.9.168-1+deb9u2~deb8u1.

We recommend that you upgrade your linux-4.9 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);