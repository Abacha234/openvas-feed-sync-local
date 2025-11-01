# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841045");
  script_cve_id("CVE-2012-0954");
  script_tag(name:"creation_date", value:"2012-06-19 04:11:47 +0000 (Tue, 19 Jun 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1477-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1477-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1477-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apt' package(s) announced via the USN-1477-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Georgi Guninski discovered that APT did not properly validate imported
keyrings via apt-key net-update. USN-1475-1 added additional verification
for imported keyrings, but it was insufficient. If a remote attacker were
able to perform a machine-in-the-middle attack, this flaw could potentially be
used to install altered packages. This update corrects the issue by
disabling the net-update option completely. A future update will re-enable
the option with corrected verification.");

  script_tag(name:"affected", value:"'apt' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
