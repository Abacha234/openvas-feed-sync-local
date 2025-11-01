# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53276");
  script_cve_id("CVE-2004-1006");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-584)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-584");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-584");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dhcp' package(s) announced via the DSA-584 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"'infamous41md' noticed that the log functions in dhcp 2.x, which is still distributed in the stable Debian release, contained pass parameters to function that use format strings. One use seems to be exploitable in connection with a malicious DNS server.

For the stable distribution (woody) these problems have been fixed in version 2.0pl5-11woody1.

For the unstable distribution (sid) these problems have been fixed in version 2.0pl5-19.1.

We recommend that you upgrade your dhcp package.");

  script_tag(name:"affected", value:"'dhcp' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);