# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840627");
  script_cve_id("CVE-2011-1400");
  script_tag(name:"creation_date", value:"2011-04-06 14:20:31 +0000 (Wed, 06 Apr 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1103-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1103-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tex-common' package(s) announced via the USN-1103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Svensson discovered that the tex-common package contains an
insecure shell_escape_commands configuration item. If a user or automated
system were tricked into opening a specially crafted TeX file, a remote
attacker could execute arbitrary code with user privileges.");

  script_tag(name:"affected", value:"'tex-common' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
