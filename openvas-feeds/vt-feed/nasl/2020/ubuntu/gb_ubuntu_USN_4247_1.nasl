# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844304");
  script_cve_id("CVE-2019-15795", "CVE-2019-15796");
  script_tag(name:"creation_date", value:"2020-01-23 04:00:24 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-19 19:38:00 +0000 (Mon, 19 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-4247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4247-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4247-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-apt' package(s) announced via the USN-4247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that python-apt would still use MD5 hashes to validate
certain downloaded packages. If a remote attacker were able to perform a
machine-in-the-middle attack, this flaw could potentially be used to install
altered packages. (CVE-2019-15795)

It was discovered that python-apt could install packages from untrusted
repositories, contrary to expectations. (CVE-2019-15796)");

  script_tag(name:"affected", value:"'python-apt' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
