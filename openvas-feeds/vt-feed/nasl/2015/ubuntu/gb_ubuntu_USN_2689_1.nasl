# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842389");
  script_cve_id("CVE-2015-1333", "CVE-2015-3290", "CVE-2015-3291", "CVE-2015-5157");
  script_tag(name:"creation_date", value:"2015-07-30 03:13:46 +0000 (Thu, 30 Jul 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2689-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2689-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2689-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic' package(s) announced via the USN-2689-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Lutomirski discovered a flaw in the Linux kernel's handling of nested
NMIs (non-maskable interrupts). An unprivileged local user could exploit
this flaw to cause a denial of service (system crash) or potentially
escalate their privileges. (CVE-2015-3290)

Colin King discovered a flaw in the add_key function of the Linux kernel's
keyring subsystem. A local user could exploit this flaw to cause a denial
of service (memory exhaustion). (CVE-2015-1333)

Andy Lutomirski discovered a flaw that allows user to cause the Linux
kernel to ignore some NMIs (non-maskable interrupts). A local unprivileged
user could exploit this flaw to potentially cause the system to miss
important NMIs resulting in unspecified effects. (CVE-2015-3291)

Andy Lutomirski and Petr Matousek discovered that an NMI (non-maskable
interrupt) that interrupts userspace and encounters an IRET fault is
incorrectly handled by the Linux kernel. An unprivileged local user could
exploit this flaw to cause a denial of service (kernel OOPs), corruption,
or potentially escalate privileges on the system. (CVE-2015-5157)");

  script_tag(name:"affected", value:"'linux-lts-utopic' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
