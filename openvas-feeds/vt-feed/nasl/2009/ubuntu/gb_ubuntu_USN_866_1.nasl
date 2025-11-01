# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66464");
  script_cve_id("CVE-2009-4641");
  script_tag(name:"creation_date", value:"2009-12-09 23:23:54 +0000 (Wed, 09 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-866-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-866-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-866-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-screensaver' package(s) announced via the USN-866-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that gnome-screensaver did not always re-enable itself
after applications requested it to ignore idle timers. This may result in the
screen not being automatically locked after the inactivity timeout is
reached, permitting an attacker with physical access to gain access to an
unlocked session.");

  script_tag(name:"affected", value:"'gnome-screensaver' package(s) on Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
