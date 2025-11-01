# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842385");
  script_cve_id("CVE-2015-1805", "CVE-2015-4700");
  script_tag(name:"creation_date", value:"2015-07-24 04:35:34 +0000 (Fri, 24 Jul 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2678-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2678-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2678-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2678-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the user space memory copying for the pipe iovecs
in the Linux kernel. An unprivileged local user could exploit this flaw to
cause a denial of service (system crash) or potentially escalate their
privileges. (CVE-2015-1805)

Daniel Borkmann reported a kernel crash in the Linux kernel's BPF filter
JIT optimization. A local attacker could exploit this flaw to cause a
denial of service (system crash). (CVE-2015-4700)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
