# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840752");
  script_tag(name:"creation_date", value:"2011-09-23 14:39:49 +0000 (Fri, 23 Sep 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1215-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1215-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1215-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/856489");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apt' package(s) announced via the USN-1215-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the apt-key utility incorrectly verified GPG
keys when downloaded via the net-update option. If a remote attacker were
able to perform a machine-in-the-middle attack, this flaw could potentially be
used to install altered packages. This update corrects the issue by
disabling the net-update option completely. A future update will re-enable
the option with corrected verification.");

  script_tag(name:"affected", value:"'apt' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
