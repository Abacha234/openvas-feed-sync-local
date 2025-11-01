# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842813");
  script_cve_id("CVE-2016-4482", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4913", "CVE-2016-4997", "CVE-2016-4998");
  script_tag(name:"creation_date", value:"2016-06-28 03:25:54 +0000 (Tue, 28 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-3018-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3018-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3018-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-3018-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jesse Hertz and Tim Newsham discovered that the Linux netfilter
implementation did not correctly perform validation when handling 32 bit
compatibility IPT_SO_SET_REPLACE events on 64 bit platforms. A local
unprivileged attacker could use this to cause a denial of service (system
crash) or execute arbitrary code with administrative privileges.
(CVE-2016-4997)

Kangjie Lu discovered an information leak in the core USB implementation in
the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4482)

Jann Horn discovered that the InfiniBand interfaces within the Linux kernel
could be coerced into overwriting kernel memory. A local unprivileged
attacker could use this to possibly gain administrative privileges on
systems where InifiniBand related kernel modules are loaded.
(CVE-2016-4565)

Kangjie Lu discovered an information leak in the timer handling
implementation in the Advanced Linux Sound Architecture (ALSA) subsystem of
the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4569, CVE-2016-4578)

Kangjie Lu discovered an information leak in the X.25 Call Request handling
in the Linux kernel. A local attacker could use this to obtain potentially
sensitive information from kernel memory. (CVE-2016-4580)

It was discovered that an information leak exists in the Rock Ridge
implementation in the Linux kernel. A local attacker who is able to mount a
malicious iso9660 file system image could exploit this flaw to obtain
potentially sensitive information from kernel memory. (CVE-2016-4913)

Jesse Hertz and Tim Newsham discovered that the Linux netfilter
implementation did not correctly perform validation when handling
IPT_SO_SET_REPLACE events. A local unprivileged attacker could use this to
cause a denial of service (system crash) or obtain potentially sensitive
information from kernel memory. (CVE-2016-4998)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
