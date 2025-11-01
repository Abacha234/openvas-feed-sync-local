# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841294");
  script_cve_id("CVE-2012-5656", "CVE-2012-6076");
  script_tag(name:"creation_date", value:"2013-01-31 03:56:22 +0000 (Thu, 31 Jan 2013)");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1712-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1712-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1712-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'inkscape' package(s) announced via the USN-1712-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Inkscape incorrectly handled XML external entities in
SVG files. If a user were tricked into opening a specially-crafted SVG
file, Inkscape could possibly include external files in drawings, resulting
in information disclosure. (CVE-2012-5656)

It was discovered that Inkscape attempted to open certain files from the
/tmp directory instead of the current directory. A local attacker could
trick a user into opening a different file than the one that was intended.
This issue only applied to Ubuntu 11.10, Ubuntu 12.04 LTS and Ubuntu 12.10.
(CVE-2012-6076)");

  script_tag(name:"affected", value:"'inkscape' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
