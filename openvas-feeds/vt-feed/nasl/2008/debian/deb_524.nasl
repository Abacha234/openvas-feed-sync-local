# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53689");
  script_cve_id("CVE-2004-0393", "CVE-2004-0454");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-524)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-524");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-524");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rlpr' package(s) announced via the DSA-524 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"discovered a format string vulnerability in rlpr, a utility for lpd printing without using /etc/printcap. While investigating this vulnerability, a buffer overflow was also discovered in related code. By exploiting one of these vulnerabilities, a local or remote user could potentially cause arbitrary code to be executed with the privileges of 1) the rlprd process (remote), or 2) root (local).

CAN-2004-0393: format string vulnerability via syslog(3) in msg() function in rlpr

CAN-2004-0454: buffer overflow in msg() function in rlpr

For the current stable distribution (woody), this problem has been fixed in version 2.02-7woody1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you update your rlpr package.");

  script_tag(name:"affected", value:"'rlpr' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);