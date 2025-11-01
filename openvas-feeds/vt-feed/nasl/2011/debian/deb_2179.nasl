# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69114");
  script_cve_id("CVE-2011-0434", "CVE-2011-0435", "CVE-2011-0436", "CVE-2011-0437");
  script_tag(name:"creation_date", value:"2011-03-09 04:54:11 +0000 (Wed, 09 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2179)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2179");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2179");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dtc' package(s) announced via the DSA-2179 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ansgar Burchardt discovered several vulnerabilities in DTC, a web control panel for admin and accounting hosting services.

CVE-2011-0434

The bw_per_moth.php graph contains an SQL injection vulnerability.

CVE-2011-0435

Insufficient checks in bw_per_month.php can lead to bandwidth usage information disclosure.

CVE-2011-0436

After a registration, passwords are sent in cleartext email messages.

CVE-2011-0437

Authenticated users could delete accounts using an obsolete interface which was incorrectly included in the package.

This update introduces a new configuration option which controls the presence of cleartext passwords in email messages. The default is not to include cleartext passwords.

For the oldstable distribution (lenny), this problem has been fixed in version 0.29.17-1+lenny1.

The stable distribution (squeeze) and the testing distribution (wheezy) do not contain any dtc packages.

For the unstable distribution (sid), this problem has been fixed in version 0.32.10-1.

We recommend that you upgrade your dtc packages.");

  script_tag(name:"affected", value:"'dtc' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);