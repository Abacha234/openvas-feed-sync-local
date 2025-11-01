# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841770");
  script_cve_id("CVE-2013-6393", "CVE-2014-2525");
  script_tag(name:"creation_date", value:"2014-04-08 06:31:34 +0000 (Tue, 08 Apr 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2161-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2161-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2161-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libyaml-libyaml-perl' package(s) announced via the USN-2161-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered that libyaml-libyaml-perl incorrectly handled
certain large YAML documents. An attacker could use this issue to cause
libyaml-libyaml-perl to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2013-6393)

Ivan Fratric discovered that libyaml-libyaml-perl incorrectly handled
certain malformed YAML documents. An attacker could use this issue to cause
libyaml-libyaml-perl to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2014-2525)");

  script_tag(name:"affected", value:"'libyaml-libyaml-perl' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
