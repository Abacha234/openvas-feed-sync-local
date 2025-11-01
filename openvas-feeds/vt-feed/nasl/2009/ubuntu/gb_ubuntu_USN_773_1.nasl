# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64174");
  script_cve_id("CVE-2009-1194");
  script_tag(name:"creation_date", value:"2009-06-05 16:04:08 +0000 (Fri, 05 Jun 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-773-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-773-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-773-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pango1.0' package(s) announced via the USN-773-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Will Drewry discovered that Pango incorrectly handled rendering text with
long glyphstrings. If a user were tricked into displaying specially crafted
data with applications linked against Pango, such as Firefox, an attacker
could cause a denial of service or execute arbitrary code with privileges
of the user invoking the program.");

  script_tag(name:"affected", value:"'pango1.0' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
