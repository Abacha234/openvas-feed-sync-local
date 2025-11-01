# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56460");
  script_cve_id("CVE-2005-4536");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-960)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-960");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-960");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmail-audit-perl' package(s) announced via the DSA-960 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The former update caused temporary files to be created in the current working directory due to a wrong function argument. This update will create temporary files in the users home directory if HOME is set or in the common temporary directory otherwise, usually /tmp. For completeness below is a copy of the original advisory text:

Niko Tyni discovered that the Mail::Audit module, a Perl library for creating simple mail filters, logs to a temporary file with a predictable filename in an insecure fashion when logging is turned on, which is not the case by default.

For the old stable distribution (woody) these problems have been fixed in version 2.0-4woody3.

For the stable distribution (sarge) these problems have been fixed in version 2.1-5sarge4.

For the unstable distribution (sid) these problems have been fixed in version 2.1-5.1.

We recommend that you upgrade your libmail-audit-perl package.");

  script_tag(name:"affected", value:"'libmail-audit-perl' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);