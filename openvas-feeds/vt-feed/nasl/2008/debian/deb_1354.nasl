# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58526");
  script_cve_id("CVE-2007-3387");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1354)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1354");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1354");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gpdf' package(s) announced via the DSA-1354 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that an integer overflow in xpdf PDF viewer may lead to the execution of arbitrary code if a malformed PDF file is opened.

gpdf includes a copy of the xpdf code and requires an update as well.

For the oldstable distribution (sarge) this problem has been fixed in version 2.8.2-1.2sarge6.

The stable distribution (etch) no longer contains gpdf.

The unstable distribution (sid) no longer contains gpdf.

We recommend that you upgrade your gpdf packages.");

  script_tag(name:"affected", value:"'gpdf' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);