# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53260");
  script_cve_id("CVE-2004-0911");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-556)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-556");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-556");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'netkit-telnet' package(s) announced via the DSA-556 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michal Zalewski discovered a bug in the netkit-telnet server (telnetd) whereby a remote attacker could cause the telnetd process to free an invalid pointer. This causes the telnet server process to crash, leading to a straightforward denial of service (inetd will disable the service if telnetd is crashed repeatedly), or possibly the execution of arbitrary code with the privileges of the telnetd process (by default, the 'telnetd' user).

For the stable distribution (woody) this problem has been fixed in version 0.17-18woody2.

For the unstable distribution (sid) this problem has been fixed in version 0.17-26.

We recommend that you upgrade your netkit-telnet package.");

  script_tag(name:"affected", value:"'netkit-telnet' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);