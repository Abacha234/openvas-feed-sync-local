# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60497");
  script_cve_id("CVE-2008-0072");
  script_tag(name:"creation_date", value:"2008-03-11 20:16:32 +0000 (Tue, 11 Mar 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1512)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1512");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1512");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'evolution' package(s) announced via the DSA-1512 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ulf Harnhammar discovered that Evolution, the e-mail and groupware suite, had a format string vulnerability in the parsing of encrypted mail messages. If the user opened a specially crafted email message, code execution was possible.

For the stable distribution (etch), this problem has been fixed in version 2.6.3-6etch2.

For the old stable distribution (sarge), this problem has been fixed in version 2.0.4-2sarge3. Some architectures have not yet completed building the updated package for sarge, they will be added as they come available.

For the unstable distribution (sid), this problem has been fixed in version 2.12.3-1.1.

We recommend that you upgrade your evolution package.");

  script_tag(name:"affected", value:"'evolution' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);