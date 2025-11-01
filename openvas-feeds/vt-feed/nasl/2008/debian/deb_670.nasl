# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53499");
  script_cve_id("CVE-2005-0100");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-670)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-670");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-670");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'emacs20' package(s) announced via the DSA-670 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Max Vozeler discovered several format string vulnerabilities in the movemail utility of Emacs, the well-known editor. Via connecting to a malicious POP server an attacker can execute arbitrary code under the privileges of group mail.

For the stable distribution (woody) these problems have been fixed in version 20.7-13.3.

The unstable distribution (sid) does not contain an Emacs20 package anymore.

We recommend that you upgrade your emacs packages.");

  script_tag(name:"affected", value:"'emacs20' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);