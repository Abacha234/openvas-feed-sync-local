# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67986");
  script_cve_id("CVE-2010-2935", "CVE-2010-2936");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2099)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2099");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2099");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-2099 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Charlie Miller has discovered two vulnerabilities in OpenOffice.org Impress, which can be exploited by malicious people to compromise a user's system and execute arbitrary code.

An integer truncation error when parsing certain content can be exploited to cause a heap-based buffer overflow via a specially crafted file.

A short integer overflow error when parsing certain content can be exploited to cause a heap-based buffer overflow via a specially crafted file.

For the stable distribution (lenny) these problems have been fixed in version 2.4.1+dfsg-1+lenny8.

For the testing (squeeze) and unstable (sid) distributions these problems have been fixed in version 3.2.1-6.

We recommend that you upgrade your openoffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);