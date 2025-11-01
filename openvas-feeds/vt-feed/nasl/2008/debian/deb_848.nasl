# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55561");
  script_cve_id("CVE-2005-2662", "CVE-2005-2663");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-848)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-848");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-848");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'masqmail' package(s) announced via the DSA-848 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jens Steube discovered two vulnerabilities in masqmail, a mailer for hosts without permanent internet connection. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-2662

When sending failed mail messages, the address is not sanitised, which allows a local attacker to execute arbitrary commands as the mail user.

CAN-2005-2663

When opening the log file, masqmail does not relinquish privileges, which allows a local attacker to overwrite arbitrary files via a symlink attack.

For the old stable distribution (woody) these problems have been fixed in version 0.1.16-2.2.

For the stable distribution (sarge) these problems have been fixed in version 0.2.20-1sarge1.

For the unstable distribution (sid) these problems have been fixed in version 0.2.20-1sarge1.

We recommend that you upgrade your masqmail package.");

  script_tag(name:"affected", value:"'masqmail' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);